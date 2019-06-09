#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/types.h>
#include <regex.h>
#include <arpa/inet.h>
#include "head.h"

bool find_url;
bool find_db;

char* check_url(const unsigned char* data){
    struct eth_header *eth = (struct eth_header *)data;
    if(ntohs(eth->eth_type) == ipv4){
        struct ip_header *ip = (struct ip_header *)(data + sizeof(*eth));
        uint16_t ipv4_len = (ip->ipv4_len & 0x0F)<<2;
        if(ip->pid == 6){
            struct tcp_header *tcp = (struct tcp_header *)((uint8_t *)ip + ipv4_len);
            uint16_t tcp_len = (tcp->hlen & 0xF0)>>2;
            if((ntohs(tcp->sport) == 80 || ntohs(tcp->dport) == 80)){
                char *http_data = (char *)((uint8_t *)tcp + tcp_len);
                uint16_t http_data_len = ntohs(ip->packet_len) - ipv4_len - tcp_len;
                if(http_data_len > 0) {
                    const char* pattern = "Host: ([A-Za-z\\.0-9]+)";
                    regex_t state;
                    regcomp(&state, pattern, REG_EXTENDED);

                    int i=0;
                    while(1){
                        char* str = (char *)malloc(1024);
                        int a=0;
                        while(1){
                            *(str+a) = *(http_data+i);
                            if(*(http_data+i+1) == 0x0d && *(http_data+i+2) == 0x0a) {
                                i += 3;
                                break;
                            }
                            if(i == http_data_len - 1) break;
                            a++;
                            i++;
                        }

                        int status = regexec(&state, str, 0, NULL, 0);
                        if(status == 0){
                            find_url = true;
                            return str;
                        }
                        if(i == http_data_len) break;
                    }
                }
            }
        }
    }
    return 0;
}

unsigned char* make_c_rst(const unsigned char* data){
    struct eth_header *eth = (struct eth_header *)data;
    struct ip_header *ip = (struct ip_header *)(data + sizeof(*eth));
    uint16_t ipv4_len = (ip->ipv4_len & 0x0F)<<2;
    struct tcp_header *tcp = (struct tcp_header *)((uint8_t *)ip + ipv4_len);
    uint16_t tcp_len = (tcp->hlen & 0xF0)>>2;
    char *http_data = (char *)((uint8_t *)tcp + tcp_len);
    uint16_t http_data_len = ntohs(ip->packet_len) - ipv4_len - tcp_len;
    uint16_t rst_packet_len = sizeof(*eth)+ipv4_len+tcp_len;

    int tmp = 0;

    for(int i=0; i<6; i++){
        tmp = *(data+i);
        eth->dmac[i] = *(data+6+i);
        eth->smac[i] = tmp;
    }
    memcpy(&ip->packet_len, &rst_packet_len, sizeof(uint16_t));
    ip->packet_len = ntohs(ip->packet_len);
    memset(&ip->id, 0, sizeof(uint16_t));
    ip->ttl = 0x50;
    tmp = ip->sip;
    memcpy(&ip->sip, data+30, sizeof(uint32_t));
    memcpy(&ip->dip, &tmp, sizeof(uint32_t));
    tmp = tcp->dport;
    memcpy(&tcp->dport, data+34, sizeof(uint16_t));
    memcpy(&tcp->sport, &tmp, sizeof(uint16_t));
    memcpy(&tcp->seqnum, data+42, sizeof(uint32_t));
    memset(&tcp->acknum, 0, sizeof(uint32_t));
    tcp->flag = 0x04;
    memset(&tcp->wsize, 0, sizeof(uint16_t));

    unsigned char* rst_packet = (unsigned char*)calloc(rst_packet_len, sizeof(uint8_t));
    memcpy(rst_packet, eth, sizeof(*eth));
    memcpy(rst_packet+sizeof(*eth), ip, sizeof(*ip));
    if(ipv4_len>20){
        memcpy(rst_packet+sizeof(*eth)+sizeof(*ip),
               data+sizeof(*eth)+sizeof(*ip), ipv4_len-sizeof(*ip));
    }
    memcpy(rst_packet+sizeof(*eth)+ipv4_len, tcp, sizeof(*tcp));
    if(tcp_len>20){
        memcpy(rst_packet+sizeof(*eth)+ipv4_len+sizeof(*tcp),
               data+sizeof(*eth)+ipv4_len+sizeof(*tcp), tcp_len-sizeof(*tcp));
    }

    uint16_t ip_checksum = 0;
    uint16_t tcp_checksum = 0;
    tmp = 0;

    for(int i=0; i<ipv4_len/2; i++){
        tmp += *(rst_packet+14+2*i)<<8;
        tmp += *(rst_packet+14+2*i+1);
    }
    tmp -= ntohs(ip->checksum);
    if(tmp>0xffff){
        tmp = tmp - (tmp&0xFFFF0000) + ((tmp&0xFFFF0000)>>16);
    }
    tmp = 0xffff-tmp;
    ip_checksum = tmp;
    tmp = 0;

    tmp += ((ntohl(ip->sip)&0xFFFF0000)>>16) + (ntohl(ip->sip)&0x0000FFFF)
            + ((ntohl(ip->dip)&0xFFFF0000)>>16) + (ntohl(ip->dip)&0x0000FFFF)
            + ip->pid + tcp_len;
    if(tmp>0xffff){
        tmp = tmp - (tmp&0xFFFF0000) + ((tmp&0xFFFF0000)>>16);
    }
    tcp_checksum = tmp;
    tmp = 0;

    for(int i=0; i<tcp_len/2; i++){
        tmp += *(rst_packet+14+ipv4_len+2*i)<<8;
        tmp += *(rst_packet+14+ipv4_len+2*i+1);
    }
    tmp -= ntohs(tcp->checksum);
    if(tmp>0xffff){
        tmp = tmp - (tmp&0xFFFF0000) + ((tmp&0xFFFF0000)>>16);
    }
    tmp += tcp_checksum;
    if(tmp>0xffff){
        tmp = tmp - (tmp&0xFFFF0000) + ((tmp&0xFFFF0000)>>16);
    }
    tcp_checksum = 0xffff-tmp;

    ip_checksum = ntohs(ip_checksum);
    tcp_checksum = ntohs(tcp_checksum);

    memcpy(rst_packet+24, &ip_checksum, sizeof(uint16_t));
    memcpy(rst_packet+50, &tcp_checksum, sizeof(uint16_t));

    return rst_packet;
}

int main(int argc, char* argv[]){
    int line_count = 0;
    char check_line[100];
    FILE *fp = fopen("test_50.csv", "r");
    while (1) {
        fscanf(fp, "%s", check_line);
        if(feof(fp)) break;
        line_count++;
    }
    fseek(fp, 0, SEEK_SET);

    char buff[line_count][100];
    char tmp[100];
    for(int i=0; i<line_count; i++) {
        fscanf(fp, "%s", buff[i]);
    }
    for(int i=0; i<line_count-1; i++){
        for(int j=0; j<line_count-1-i; j++){
            if(strcmp(buff[j],buff[j+1])>0){
                strcpy(tmp, buff[j]);
                strcpy(buff[j], buff[j+1]);
                strcpy(buff[j+1], tmp);
            }
        }
    }

    for(int i=0; i<50; i++){
        printf("%d : %s\n", i+1, *(buff+i));
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    char* domain;
    while(1){
        find_url = false;
        find_db = false;
        struct pcap_pkthdr* header;
        const unsigned char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res==0) continue;
        domain = check_url(packet);
        if(find_url == true){
            domain = domain+6;
            int first = 1;
            int last = line_count;
            int mid;
            while(first <= last){
                mid = (first+last)/2;
                if(memcmp(domain, buff[mid], sizeof(domain)) == 0){
                    find_db = true;
                    break;
                }
                else{
                    if(memcmp(domain, buff[mid], sizeof(domain)) > 0){
                        first = mid+1;
                    }
                    else{
                        last = mid-1;
                    }
                }
            }
        }
        if(find_db == true){
            printf("%s  find DB\n",domain);
            unsigned char * rst_c_packet = make_c_rst(packet);

            struct eth_header *eth = (struct eth_header *)packet;
            struct ip_header *ip = (struct ip_header *)(packet + sizeof(*eth));
            uint16_t ipv4_len = (ip->ipv4_len & 0x0F)<<2;
            struct tcp_header *tcp = (struct tcp_header *)((uint8_t *)ip + ipv4_len);
            uint16_t tcp_len = (tcp->hlen & 0xF0)>>2;

            int rst_packet_len = sizeof(*eth) + ipv4_len + tcp_len;

            pcap_sendpacket(handle, rst_c_packet, rst_packet_len);
        }
    }

}
