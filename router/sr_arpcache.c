#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"


/*
 This function gets called every second. For each request sent out, we keep
 checking whether we should resend an request or destroy the arp request.
 See the comments in the header file for an idea of what it should look like.
 */
struct sr_if* IpGetAddr(struct sr_instance* sr, in_addr_t destIp)
{
    struct sr_rt* route = sr->routing_table;
    int networkMaskLength = -1;
    struct sr_rt* rtrt = NULL;
    
    //for (routeIter = sr->routing_table; routeIter; routeIter = routeIter->next)
    while(route)
    {
        int len = 0;
        uint32_t temp = 0x80000000;
        while ((temp != 0) && ((temp & route->mask.s_addr) != 0))
        {
            temp >>= 1;
            len++;
        }
        if (len > networkMaskLength)
        {
            if ((destIp & route->mask.s_addr) == (ntohl(route->dest.s_addr) & route->mask.s_addr))
            {
                rtrt = route;
                networkMaskLength = len;
            }
        }
        route = route->next;
    }
    struct sr_if* inter= sr_get_interface(sr,rtrt->interface);
    return inter;
}

void SendIcmp(struct sr_instance* sr, uint8_t* packet)
{
    
    struct sr_if* destinationInterface;
    
    uint8_t* replyPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                                  + sizeof(sr_icmp_t3_hdr_t));
    sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
                                                             + sizeof(sr_ip_hdr_t));
    
    sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*) replyPacket;
    //ether header
    struct sr_ethernet_hdr* ether_hdr = 0;
    struct sr_ip_hdr* ip_hdr = 0;
    ether_hdr = (struct sr_ethernet_hdr*)packet;
    ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    uint8_t eshost[ETHER_ADDR_LEN];
    memcpy(eshost, ether_hdr->ether_shost, ETHER_ADDR_LEN);
    
    struct sr_if* interfaceIterator;
    
    for (interfaceIterator = sr->if_list; interfaceIterator != NULL; interfaceIterator = interfaceIterator->next)
    {
        if (ip_hdr->ip_src == interfaceIterator->ip)
        {
            free(replyPacket);
            return;
        }
    }
    
    ethernetHdr->ether_type = htons(ethertype_arp);
    /* Fill in IP header */
    replyIpHeader->ip_v = 4;
    replyIpHeader->ip_hl = 4;
    replyIpHeader->ip_tos = 0;
    replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    replyIpHeader->ip_id = htons(ipIdentifyNumber); ipIdentifyNumber++;
    replyIpHeader->ip_off = htons(IP_DF);
    replyIpHeader->ip_ttl = DEFAULT_TTL;
    replyIpHeader->ip_p = ip_protocol_icmp;
    replyIpHeader->ip_sum = 0;
    replyIpHeader->ip_dst = ip_hdr->ip_src;
    
    
    destinationInterface = IpGetAddr(sr, ntohl(replyIpHeader->ip_dst));
    
    replyIpHeader->ip_src = destinationInterface->ip;
    replyIpHeader->ip_sum = cksum((void*)replyIpHeader, sizeof(sr_ip_hdr_t));
    
    //ICMP header
    replyIcmpHeader->icmp_type = 3;
    replyIcmpHeader->icmp_code = 0;
    replyIcmpHeader->icmp_sum = 0;
    memcpy(replyIcmpHeader->data, ip_hdr, ICMP_DATA_SIZE);
    replyIcmpHeader->icmp_sum = cksum((void*)replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));
    
    //Ethernet Header
    memcpy(ethernetHdr->ether_dhost, eshost, ETHER_ADDR_LEN);
    memcpy(ethernetHdr->ether_shost, destinationInterface->addr, ETHER_ADDR_LEN);
    
    //send packet
    sr_send_packet(sr, replyPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),destinationInterface->name);
    
    free(replyPacket);
}


void handle_arpreq(struct sr_arpreq* req, struct sr_instance *sr){
    time_t curtime = time(NULL);
    
    
    if (difftime(curtime, req->sent) >= 1) {
        if(req->times_sent >= 5)
        {
            //send icmp host unreachable to source addr of all pkts waiting
            
            struct sr_packet * packet;
            //fprintf(stderr, "ARP request timed out. Sending unreachable packets.\n");
            
            for (packet= req->packets; packet != NULL; packet = packet->next)
            {
                SendIcmp(sr, packet->buf);
            }
            sr_arpreq_destroy(&sr->cache, req);
            
        }
        else
        {
            //send arp request
            uint8_t* arpPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*) arpPacket;
            sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*) (arpPacket + sizeof(sr_ethernet_hdr_t));
            
            struct sr_if* interface = IpGetAddr(sr, req->ip);
            unsigned char s_addr[ETHER_ADDR_LEN];
            memcpy(s_addr, interface->addr, ETHER_ADDR_LEN);
            
            /* Ethernet Header */
            memcpy(ethernetHdr->ether_dhost, broadcastEthertAddr, ETHER_ADDR_LEN);
            memcpy(ethernetHdr->ether_shost, s_addr, ETHER_ADDR_LEN);
            ethernetHdr->ether_type = htons(ethertype_arp);
            
            /* ARP Header */
            arpHdr->ar_hrd = htons(arp_hrd_ethernet);
            arpHdr->ar_pro = htons(ethertype_ip);
            arpHdr->ar_hln = ETHER_ADDR_LEN;
            arpHdr->ar_pln = 4;
            arpHdr->ar_op = htons(arp_op_request);
            memcpy(arpHdr->ar_sha, s_addr, ETHER_ADDR_LEN);
            arpHdr->ar_sip = interface->ip;
            memset(arpHdr->ar_tha, 0, ETHER_ADDR_LEN);
            arpHdr->ar_tip = htonl(req->ip);
            
            sr_send_packet(sr, arpPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),interface->name);
            
            free(arpPacket);
            //set
            req->sent = curtime;
            req->times_sent++;
        }
    }
    
}
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    /* Fill this in */
    struct sr_arpreq* request = sr->cache.requests;
    while(request)
    {
        handle_arpreq(request, sr);
        request = request->next;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
 You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
     table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
 the queue, adds the packet to the linked list of packets for this sr_arpreq
 that corresponds to this ARP request. You should free the passed *packet.
 
 A pointer to the ARP request is returned; it should not be freed. The caller
 can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
 1) Looks up this IP in the request queue. If it is found, returns a pointer
 to the sr_arpreq with this IP. Otherwise, returns NULL.
 2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            }
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
 entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                }
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
 more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
        
        time_t curtime = time(NULL);
        
        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);
        
        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

