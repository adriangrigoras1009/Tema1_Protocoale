#include <queue.h>

#include "skel.h"

struct route_table
{
    uint32_t prefix;
    uint32_t next_hop;
    uint32_t mask;
    int interface;
} __attribute__((packed));

typedef struct arp_table
{
    uint32_t ip;
    uint8_t mac[6];
} arp_table;

void read_rtable(FILE *f, struct route_table rtable[], int *index) {
    char my_string[1000];
    while (1) {
        if (fgets(my_string, 1000, f) != NULL) {
            char *pch = strtok(my_string, " ");
            struct in_addr *inp = malloc(sizeof(struct in_addr));
            inet_aton(pch, inp);
            rtable[*index].prefix = inp->s_addr;
            pch = strtok(NULL, " ");
            inet_aton(pch, inp);
            rtable[*index].next_hop = inp->s_addr;
            pch = strtok(NULL, " ");
            inet_aton(pch, inp);
            rtable[*index].mask = inp->s_addr;
            pch = strtok(NULL, " ");
            rtable[*index].interface = atoi(pch);
            (*index)++;
        }
        else {
            break;
        }
    }
}

struct route_table *caut(int s, int d, __u32 dest_ip, struct route_table *rtable) {
    if (s > d)
        return NULL;
    else {
        int mijloc = (s + d) / 2;
        if ((dest_ip & rtable[mijloc].mask) == rtable[mijloc].prefix)
            return &rtable[mijloc];
        if ((dest_ip & rtable[mijloc].mask) < rtable[mijloc].prefix)
            return caut(s, mijloc-1, dest_ip, rtable);
        else
            return caut(mijloc+1, d, dest_ip, rtable);
    }
}
struct route_table *get_best_route(__u32 dest_ip, struct route_table *rtable, int index_rtable) {
    return caut(0, index_rtable - 1, dest_ip, rtable);
}

struct arp_table *get_arp_entry(__u32 ip, struct arp_table *tabela, int index_arp) {
    for (int i = 0; i < index_arp; i++) {
        if (tabela[i].ip == ip)
            return &tabela[i];
    }
    return NULL;
}
int cmpfunc(const void *a, const void *b) {
    struct route_table a1 = (*(struct route_table *)a);
    struct route_table b1 = (*(struct route_table *)b);
    return (int)((a1.prefix) - (b1.prefix));
}

int main(int argc, char *argv[])
{
    packet m;
    int rc;

    init(argc - 2, argv + 2);

    FILE *f;
    f = fopen(argv[1], "r");
    if (f == NULL) {
        perror("Nu exista tabela de rutare");
        exit(-1);
    }
    struct route_table rtable[64300];
    int index_rtable = 0;
    struct arp_table tabela_arp[64300];
    int index_arp = 0;
    read_rtable(f, rtable, &index_rtable);
    queue q = queue_create();
    qsort(rtable, index_rtable, sizeof(struct route_table), cmpfunc);
    while (1) {
        rc = get_packet(&m);
        DIE(rc < 0, "get_message");
        struct arp_header *arp = parse_arp(m.payload);
        struct icmphdr *icmp = parse_icmp(m.payload);
        struct ether_header *eth_hdr = (struct ether_header *)m.payload;
        struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
        struct in_addr *ip_de_transf = malloc(sizeof(struct in_addr));
        inet_aton(get_interface_ip(m.interface), ip_de_transf);
        if (arp == NULL) {
            if (ip_de_transf->s_addr == ip_hdr->daddr) {
                send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
                          eth_hdr->ether_shost, ICMP_ECHOREPLY, icmp->code, m.interface,
                          icmp->un.echo.id, icmp->un.echo.sequence);
                continue;
            }
            if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
                continue;
            }
            if (ip_hdr->ttl <= 1) {
                send_icmp_error(ip_hdr->saddr, ip_de_transf->s_addr,
                                eth_hdr->ether_shost, eth_hdr->ether_dhost,
                                ICMP_TIME_EXCEEDED, 0, m.interface);
                continue;
            }
            (ip_hdr->ttl)--;
            ip_hdr->check = 0;
            ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
            struct route_table *best = get_best_route(ip_hdr->daddr, rtable, index_rtable);
            if (best == NULL) {
                send_icmp_error(ip_hdr->saddr, ip_de_transf->s_addr,
                                eth_hdr->ether_dhost, eth_hdr->ether_shost,
                                ICMP_DEST_UNREACH, 0, m.interface);
                continue;
            }
            struct arp_table *arp_entry = get_arp_entry(best->next_hop, tabela_arp, index_arp);
            if (arp_entry == NULL) {
                packet *t = malloc(sizeof(packet));
                memcpy(t, &m, sizeof(packet));
                queue_enq(q, t);
                get_interface_mac(best->interface, eth_hdr->ether_shost);
                memset(eth_hdr->ether_dhost, 0xff, 6);
                eth_hdr->ether_type = htons(ETHERTYPE_ARP);
                uint32_t adr_source = ip_de_transf->s_addr;
                send_arp(best->next_hop, adr_source, eth_hdr, best->interface,
                         htons(ARPOP_REQUEST));
            }
            else {
                get_interface_mac(best->interface, eth_hdr->ether_shost);
                memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETH_ALEN);
                send_packet(best->interface, &m);
            }
        }
        else if (arp != NULL) {
            if (htons(arp->op) == ARPOP_REQUEST) {
                for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
                    struct in_addr *inp = malloc(sizeof(struct in_addr *));
                    inet_aton(get_interface_ip(i), inp);
                    if (arp->tpa == inp->s_addr) {
                        uint8_t mac_addr[6];
                        get_interface_mac(m.interface, mac_addr);
                        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
                        memcpy(eth_hdr->ether_shost, mac_addr, ETH_ALEN);
                        send_arp(arp->spa, arp->tpa, eth_hdr, m.interface, htons(ARPOP_REPLY));
                        break;
                    }
                }
            }
            else if (htons(arp->op) == ARPOP_REPLY) {
            	tabela_arp[index_arp].ip = arp->spa;
            	memcpy(tabela_arp[index_arp].mac, eth_hdr->ether_shost, ETH_ALEN);
                index_arp++;
                queue aux_q = queue_create();
                while (!queue_empty(q)) {
                    packet *n = queue_deq(q);
                    struct ether_header *eth_hdr_pachet = (struct ether_header *)n->payload;
                    struct iphdr *ip_hdr_pachet = (struct iphdr *)(n->payload + sizeof(struct ether_header));
                    struct route_table *best = get_best_route(ip_hdr_pachet->daddr, rtable, index_rtable);
                    if (best->next_hop == arp->spa) {
                      //  get_interface_mac(best->interface, eth_hdr_pachet->ether_shost);
                        memcpy(eth_hdr_pachet->ether_dhost, tabela_arp[index_arp-1].mac, ETH_ALEN);
                        send_packet(best->interface, n);
                        free(n);
                    }
                    else {
                        queue_enq(aux_q, n);
                    }
                }
                q = aux_q;
            }
        }
    }
}
