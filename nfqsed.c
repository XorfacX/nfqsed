/*
Copyright (c) 2015 Radoslav Gerganov <rgerganov@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>

struct ip_hdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t sum;
    uint16_t src[2];
    uint16_t dst[2];
};

struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    unsigned int seq;
    unsigned int ack;
    uint8_t off;
    uint8_t flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
};

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t length;
    uint16_t sum;
};

#define IP_HL(ip)   (((ip)->vhl) & 0x0f)
#define TH_OFF(th)  (((th)->off & 0xf0) >> 4)

int verbose = 0;
int daemon_mode = 0;
uint8_t tcp_flags = 0x1; // default use FIN.
int queue_num = 0;

// Use a static packet here to replace tcp to udp and vice versa.
uint8_t tmp_pkt[1500];

void usage()
{
    fprintf(stderr, "Usage: nfqsed [-v] [-t flags] [-q num]\n"
            " -q num           - bind to queue with number 'num' (default 0)\n"
            " -t flags         - tcp flags used, in decimal, on byte\n"
            " -d                - daemon mode\n"
            "  -v               - be verbose\n");
    exit(1);
}

uint16_t ip_sum(uint16_t len_ip_hdr, uint8_t *buff) {
    uint32_t sum = 0;
    int i = 0;

    for (i=0; i<(len_ip_hdr/2); i++) {
        sum += ntohs((buff[i*2+1] << 8) | buff[i*2]);
    }
    if ((len_ip_hdr % 2) == 1) {
        sum += buff[len_ip_hdr-1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;
    return htons((uint16_t) sum);
}

uint16_t tcp_sum(uint16_t len_tcp, uint16_t *src_addr, uint16_t *dest_addr, uint8_t *buff)
{
    uint16_t prot_tcp = 6;
    uint32_t sum = 0;
    int i = 0;

    sum += ntohs(src_addr[0]);
    sum += ntohs(src_addr[1]);
    sum += ntohs(dest_addr[0]);
    sum += ntohs(dest_addr[1]);
    sum += len_tcp;
    sum += prot_tcp;
    for (i=0; i<(len_tcp/2); i++) {
        sum += ntohs((buff[i*2+1] << 8) | buff[i*2]);
    }
    if ((len_tcp % 2) == 1) {
        sum += buff[len_tcp-1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;
    return htons((uint16_t) sum);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    int id = 0, len = 0, tmp_len = 0;
    struct nfqnl_msg_packet_hdr *ph;
    uint8_t *payload=NULL, *tcp_payload, *pos;
    struct ip_hdr *ip;
    struct tcp_hdr *tcp;
    uint16_t ip_size = 0, tcp_size = 0;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    len = nfq_get_payload(nfa, &payload);
    if (len < 0) {
        fprintf(stderr, "Error getting payload\n");
        return len;
    }

    // ZDY:
    // change udp protocol to tcp protocol if this is a
    // udp packet, we will test whether firewall will
    // filter own packet because it's a fake tcp...

    // Note: FW not allow this to pass, we must
    // extract payload and add a tcp header.
    // tcp syn packet can have data, so we always
    // make a tcp syn packet here.

    // SYN packet with data not work because FW
    // will limit the connection setup rate.
    // We switch to FIN packet with data.

    ip = (struct ip_hdr*) payload;

    if ((ip->proto != 17) && (ip->proto != 6)) {
        // only tcp/udp is supported
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    // Do the swap.
    if (ip->proto == 17) {
        struct ip_hdr *tmp_ip;
        struct tcp_hdr *tmp_tcp;
        struct udp_hdr *udp;
        uint16_t udp_payload_len;

        ip_size = IP_HL(ip)*4;
        udp = (struct udp_hdr*)((uint8_t*)payload + ip_size);
        udp_payload_len = ntohs(udp->length) - sizeof(struct udp_hdr);
        // build up ip header.
        memcpy((uint8_t*)tmp_pkt, (uint8_t*)ip, ip_size);
        tmp_ip = (struct ip_hdr*) tmp_pkt;
        tmp_ip->proto = 6;
        tmp_ip->sum = 0;
        // Fix up ip total length.
        tmp_ip->len = htons(udp_payload_len + sizeof(struct tcp_hdr) + ip_size);
        tmp_ip->sum = ip_sum(ip_size, tmp_ip);
        // copy udp payload, and leave space for tcp hdr.
        memcpy((uint8_t*)tmp_pkt+ip_size+sizeof(struct tcp_hdr),
               (uint8_t*)udp + sizeof(struct udp_hdr),
               udp_payload_len);
        tmp_tcp = (struct tcp_hdr *)((uint8_t*)tmp_pkt+ip_size);
        // build up fake tcp syn header.
        // TODO: make configurable??
        tmp_tcp->sport = htons(21);
        tmp_tcp->dport = htons(32767);
        tmp_tcp->seq = htonl((udp->sport<<16)|udp_dport); // a simple protocol to encode udp port to tcp seq.
        tmp_tcp->ack = htonl(1);
        tmp_tcp->off = 0x50; // 5*word, 20bits.
        tmp_tcp->flags = tcp_flags;
        tmp_tcp->win = htons(1500); // any value is ok.
        tmp_tcp->urp = 0;
        tmp_tcp->sum = 0;
        tmp_tcp->sum = tcp_sum(sizeof(struct tcp_hdr) + udp_payload_len,
                               ip->src, ip->dst,
                               (uint8_t*) tmp_tcp);
        //fix up tmp len.
        tmp_len = ip_size + sizeof(struct tcp_hdr) + udp_payload_len;
    } else {
        struct ip_hdr *tmp_ip;
        struct udp_hdr *tmp_udp;
        struct tcp_hdr *tcp;
        uint16_t tcp_payload_len;

        ip_size = IP_HL(ip)*4;
        tcp = (struct tcp_hdr*)((uint8_t*)payload + ip_size);
        tcp_payload_len = ntohs(ip->len) - sizeof(struct tcp_hdr) - ip_size;
        // build up ip header.
        memcpy((uint8_t*)tmp_pkt, (uint8_t*)ip, ip_size);
        tmp_ip = (struct ip_hdr*) tmp_pkt;
        tmp_ip->proto = 17;
        tmp_ip->sum = 0;
        // Fix up ip total length.
        tmp_ip->len = htons(tcp_payload_len + sizeof(struct udp_hdr) + ip_size);
        tmp_ip->sum = ip_sum(ip_size, tmp_ip);
        // copy tcp payload, and leave space for udp hdr.
        memcpy((uint8_t*)tmp_pkt+ip_size+sizeof(struct udp_hdr),
               (uint8_t*)tcp + sizeof(struct tcp_hdr),
               tcp_payload_len);
        tmp_udp = (struct udp_hdr *)((uint8_t*)tmp_pkt+ip_size);
        // build up fake tcp syn header.
        // recover udp s/p port from tcp seq.
        tmp_udp->sport = ntohl(tcp->seq)>>16;
        tmp_udp->dport = ntohl(tcp->seq) & 0xffff;
        tmp_udp->length = htons(tcp_payload_len + sizeof(struct udp_hdr));
        tmp_udp->sum = 0;//udp checksum zero is allowed.
        //fix up tmp len.
        tmp_len = ip_size + sizeof(struct udp_hdr) + tcp_payload_len;
    }

    /* ip_size = IP_HL(ip)*4; */
    /* tcp = (struct tcp_hdr*)(payload + ip_size); */
    /* tcp_size = TH_OFF(tcp)*4; */
    /* tcp_payload = (uint8_t*)(payload + ip_size + tcp_size); */
    /* tcp->sum = 0; */
    /* tcp->sum = tcp_sum(len-ip_size, ip->src, ip->dst, (uint8_t*) tcp); */
    return nfq_set_verdict(qh, id, NF_ACCEPT, tmp_len, tmp_pkt);
}

void read_queue()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '%d'\n", queue_num);
    qh = nfq_create_queue(h, queue_num, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        if (verbose) {
            printf("packet received\n");
        }
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);
}

int main(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "vdt:q:")) != -1) {
        switch (opt) {
            case 'v':
                verbose = 1;
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 'q':
                queue_num = atoi(optarg);
                break;
            case 't':
                tcp_flags = atoi(optarg);
                break;
            default:
                usage();
        }
    }

    if( daemon_mode ){
        int fd;

        if(fork())
            exit(0);

        /* Direct stdin,stdout,stderr to '/dev/null' */
        fd = open("/dev/null", O_RDWR);
        close(0); dup(fd);
        close(1); dup(fd);
        close(2); dup(fd);
        close(fd);

        setsid();

        chdir("/");
    }

    read_queue();
    return 0;
}
