
/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <string.h>
#include <stdlib.h>

#define MIN_IP_HEADER_LENGTH  (5)
#define DEFAULT_TTL           (64)
#define SUPPORTED_IP_VERSION  (4)
#define ETH_HEADER_LENGTH     (14)
#define IP_HEADER_LENGTH      (20)
#define ICMP_HEADER_LENGTH    (4)
#define ARP_HEADER_LENGTH     (28)


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);
    
    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));
    
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;
    
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    
} /* -- sr_init -- */



// check if we should drop ip packet
int check_ip_packet_valid(sr_ip_hdr_t *ip_hdr, unsigned int len)
{
    // drop the packet if its IPv6
    if (ip_hdr->ip_v != SUPPORTED_IP_VERSION)
    {
        fprintf (stderr, "Dropping ip packet. Version not supported.\n");
        return 0;
    }
    
    // drop packet if it does not have the min length of an arp packet
    if (len < sizeof(sr_ip_hdr_t))
    {
        fprintf (stderr, "Dropping ip packet. Too short. len: %d.\n", len);
        return 0;
    }
    
    // drop the packet if the header checksum verification fails
    uint16_t checksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0; // set to zero
    
    // checksum only compute over the header
    if (cksum((void *)ip_hdr, sizeof(sr_ip_hdr_t)) != checksum)
    {
        fprintf (stderr, "Dropping ip packet. Corrupted checksum.\n");
        return 0;
    }
    return 1;
}

// check if we should drop icmp packet
int check_icmp_packet_valid(struct sr_icmp_hdr* icmp_hdr, unsigned int len)
{ 
    uint16_t checksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    if(cksum((void *)icmp_hdr, len) != checksum) // icmp packet corrupt
    {
        fprintf(stderr, "Dropping icmp packet. Corrupted checksum\n");
        return 0;
    }
    return 1;
}

// check if two mac address equal
int check_mac_addr_equal(struct sr_if* iface, const uint8_t *add3)
{
    while(iface != NULL)
    {
        const uint8_t* add2 = add3;
        uint8_t* add1 = iface->addr;
	//print_addr_eth(add1);
        for (int i = 0; i < 6; ++i)
        {
	    if (*add1 != *add2)
                break;
            add1 = add1 + 1;
            add2 = add2 + 1;
        }
	if(*(add1-1) == *(add2-1))
	{
	    printf("packet for me!\n");
            return 1;
	}
	iface = iface->next;
    }
    printf("packet not for me!\n");
    return 0;
}

int check_ip_addr_equal(struct sr_if* iface, const uint32_t ip)
{
    while(iface != NULL)
    {
	if(iface->ip == ip){
	    printf("packet is for me!\n");
	    return 1;
	}
	iface = iface->next;
    }
    printf("packet not for me!\n");
    return 0; 
}

// handle the packets that has already expired
void ip_handle_expire(struct sr_instance* sr, uint8_t* packet, sr_ethernet_hdr_t* eth_hdr,
                      unsigned int len, char* iface)
{
    printf("ip packet expired\n");
    uint8_t* tm = malloc(6);
    memcpy(tm, eth_hdr->ether_shost, 6);
    memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
    memcpy(eth_hdr->ether_dhost, tm, 6);

    uint8_t* reply = malloc(len);
    memcpy(reply, eth_hdr, ETH_HEADER_LENGTH);
    sr_ip_hdr_t* ip_hdr = malloc(sizeof(sr_ip_hdr_t));
    uint8_t* payload = malloc(len - 38);
    memcpy(payload, reply + ETH_HEADER_LENGTH + IP_HEADER_LENGTH + ICMP_HEADER_LENGTH, len - 38);
    
    ip_hdr->ip_v = SUPPORTED_IP_VERSION;
    ip_hdr->ip_hl = MIN_IP_HEADER_LENGTH;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip_hdr->ip_id = htons(ipIdentifyNumber);
    ipIdentifyNumber++;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_p = ip_protocol_icmp;
    uint32_t tmp = ip_hdr->ip_dst;
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = tmp;
    ip_hdr->ip_ttl = DEFAULT_TTL;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((void*)ip_hdr, sizeof(sr_ip_hdr_t));
    
    struct sr_icmp_hdr* icmp_exp = malloc(sizeof(struct sr_icmp_hdr));
    icmp_exp->icmp_type = 11;
    icmp_exp->icmp_code = 0;
    icmp_exp->icmp_sum = 0;
    
    memcpy(reply + ETH_HEADER_LENGTH, ip_hdr, IP_HEADER_LENGTH);
    memcpy(reply + ETH_HEADER_LENGTH + IP_HEADER_LENGTH, icmp_exp, ICMP_HEADER_LENGTH);
    memcpy(reply + ETH_HEADER_LENGTH + IP_HEADER_LENGTH + ICMP_HEADER_LENGTH, payload, len - 38);
    sr_send_packet(sr, reply, len, iface); // send to interface
}

// send arp request
void send_arp_request(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, uint32_t ip)
{
    sr_arpcache_queuereq(&sr->cache, ip, packet, len, interface);
    handle_arpreq(sr->cache.requests, sr);
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    
    print_hdrs (packet, len); // print all possible header
    
    struct sr_if *iface = sr_get_interface(sr, interface);
    
    printf("\n");
    printf("*** -> Received packet of length %d \n", len);
    printf(" %d \n", len);
    
    if (len < ETH_HEADER_LENGTH) // drop packet if ethernet frame is too short
    {
        fprintf (stderr, "Dropping ethernet frame. Too short. len: %d.\n", len);
        return;
    }

    // ethernet frame
    sr_ethernet_hdr_t* eth_h = malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(eth_h, packet, ETH_HEADER_LENGTH);
    print_hdr_eth((uint8_t*)eth_h);
    
    // ip packet
    if(ntohs(eth_h->ether_type) == ethertype_ip)
    {
        sr_ip_hdr_t* ip_h = malloc(sizeof(sr_ip_hdr_t));
        memcpy(ip_h, packet + ETH_HEADER_LENGTH, IP_HEADER_LENGTH);

	print_hdr_ip((uint8_t*)ip_h);

        uint32_t ip_dst = ip_h->ip_dst;
        if(check_ip_packet_valid(ip_h, len - ETH_HEADER_LENGTH) == 0) // check if ip packet should be drop;
            return;
        
	//print_addr_eth(eth_h->ether_dhost);
        // packet is for me
        if(check_ip_addr_equal(sr->if_list, ip_h->ip_dst) == 1)
        {
	    // icmp packet
            if(ip_h->ip_p == ip_protocol_icmp)
            {
                struct sr_icmp_hdr* icmp_echo = malloc(sizeof(struct sr_icmp_hdr));
                memcpy(icmp_echo, packet + ETH_HEADER_LENGTH + IP_HEADER_LENGTH, ICMP_HEADER_LENGTH);

		print_hdr_icmp((uint8_t*) icmp_echo);

		struct sr_icmp_hdr* check = (struct sr_icmp_hdr*)(packet + ETH_HEADER_LENGTH + IP_HEADER_LENGTH);
                if(check_icmp_packet_valid(check, len - 34) == 0) // icmp packet corrupt                    
		    return;
                
                icmp_echo->icmp_type = 0; // icmp echo
                icmp_echo->icmp_code = 0; // icmp echo
                icmp_echo->icmp_sum = 0; // set checksum to zero
                icmp_echo->icmp_sum = cksum((void *)(packet+ETH_HEADER_LENGTH+IP_HEADER_LENGTH), len - 34); // modify?
                
                uint8_t* payload = malloc(len - 38);
                memcpy(payload, packet + ETH_HEADER_LENGTH+IP_HEADER_LENGTH+ICMP_HEADER_LENGTH, len - 38);
                
                uint8_t* tmp = malloc(6);
                memcpy(tmp, eth_h->ether_dhost, 6); // exchabge mac dhost and shost
                memcpy(eth_h->ether_dhost, eth_h->ether_shost, 6);
                memcpy(eth_h->ether_shost, tmp, 6);
                
                uint32_t t = ip_h->ip_dst; // exchange ip dst and ip src
                ip_h->ip_dst = ip_h->ip_src;
                ip_h->ip_src = t;
		ip_h->ip_ttl = DEFAULT_TTL;
                ip_h->ip_id = htons(ipIdentifyNumber);
                ipIdentifyNumber++;
                ip_h->ip_sum = 0; // set checksum to zero
                ip_h->ip_sum = cksum((void *)(ip_h), IP_HEADER_LENGTH); // compute new ip header checksum
                
		uint8_t* icmp_packet = malloc(len);
                memcpy(icmp_packet, eth_h, ETH_HEADER_LENGTH);
                memcpy(icmp_packet + ETH_HEADER_LENGTH, ip_h, IP_HEADER_LENGTH);
                memcpy(icmp_packet + ETH_HEADER_LENGTH+IP_HEADER_LENGTH, icmp_echo, ICMP_HEADER_LENGTH);
                memcpy(icmp_packet +ETH_HEADER_LENGTH+IP_HEADER_LENGTH+ICMP_HEADER_LENGTH, payload, len - 38);
                sr_send_packet(sr, icmp_packet, len, interface); // send to original interface
            }
            else // tcp/udp packet
            {
		printf("tcp/udp packet: %d\n", 3);                
		struct sr_icmp_hdr* icmp_unreach = malloc(sizeof(struct sr_icmp_hdr));
                icmp_unreach->icmp_code = 1; // host unreachable
                icmp_unreach->icmp_type = 3; // icmp unreachable
                icmp_unreach->icmp_sum = 0; // set checksum to zero
                icmp_unreach->icmp_sum = cksum((void *)(packet + ETH_HEADER_LENGTH+IP_HEADER_LENGTH), len - 34); // modify?
                
                uint8_t* payload = malloc(len - 38);
                memcpy(payload, packet + ETH_HEADER_LENGTH+IP_HEADER_LENGTH+ICMP_HEADER_LENGTH, len - 38);
                
                
                uint8_t* tmp = malloc(6);
                memcpy(tmp, eth_h->ether_dhost, 6); // exchabge mac dhost and shost
                memcpy(eth_h->ether_dhost, eth_h->ether_shost, 6);
                memcpy(eth_h->ether_shost, tmp, 6);
                
                uint32_t t = ip_h->ip_dst; // exchange ip dst and ip src
                ip_h->ip_dst = ip_h->ip_src;
                ip_h->ip_src = t;
		ip_h->ip_ttl = DEFAULT_TTL;
                ip_h->ip_id = htons(ipIdentifyNumber);
                ipIdentifyNumber++;
                ip_h->ip_sum = 0; // set checksum to zero
                ip_h->ip_sum = cksum((void *)(ip_h), IP_HEADER_LENGTH); // compute new ip header checksum
                
		uint8_t* icmp_packet = malloc(len);
                memcpy(icmp_packet, eth_h, ETH_HEADER_LENGTH);
                memcpy(icmp_packet + ETH_HEADER_LENGTH, ip_h, IP_HEADER_LENGTH);
                memcpy(icmp_packet + ETH_HEADER_LENGTH+IP_HEADER_LENGTH, icmp_unreach, ICMP_HEADER_LENGTH);
                memcpy(icmp_packet + ETH_HEADER_LENGTH+IP_HEADER_LENGTH+ICMP_HEADER_LENGTH, payload, len - 38);
                sr_send_packet(sr, icmp_packet, len, interface); // send to original interface
                return;
            }
        }
        else // packet is not for me
        {
            // using longest prefix matching
            struct sr_rt* rt_walker = sr->routing_table; // check routing table
	    struct sr_rt* router = NULL;
            char* interface_new = rt_walker->interface; // default interface
            int max_match = 0;
            rt_walker = rt_walker->next; // go to first one
            
            while(rt_walker != NULL){
                int idx = 1;
                int count = 0; // length of mask
                while(idx <= 32){
                    if(((rt_walker->mask.s_addr >> idx) & 1) == 1)
                        count++;
                    idx++;
                }

                uint32_t ip_tmp = (rt_walker->mask.s_addr) & ntohl(ip_dst);
                if(ip_tmp == (ntohl(rt_walker->dest.s_addr) & rt_walker->mask.s_addr) && count > max_match) // if prefix == network
                {
                    interface_new = rt_walker->interface;
                    max_match = count;
		    router = rt_walker;
                }
                rt_walker = rt_walker->next;
            }
	    printf("max_match length: %d\n", max_match);
	    printf("forward to interface: ");
	    printf("%s\n", interface_new);
            
            // check arp cache of the next hop;
            struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, ntohl(router->gw.s_addr));
            if(arp_entry != NULL) // can find arp entry in cache
            {
		printf("can find dst mac in arp cache\n");  
                ip_h->ip_ttl = ip_h->ip_ttl - 1; // ttl decrement by 1
                if(ip_h->ip_ttl == 0) // if time expired
                {
                    ip_handle_expire(sr, packet, eth_h, len, interface_new); // send icmp time exceed;
                    return;
                }
                
                ip_h->ip_id = htons(ipIdentifyNumber);
                ipIdentifyNumber++;
                ip_h->ip_sum = 0; // set checksum to zero
                ip_h->ip_sum = cksum((void *)(ip_h), IP_HEADER_LENGTH); // compute new ip header checksum

		struct sr_if* eth_if = sr_get_interface(sr, interface_new);              
		uint8_t* mac_tmp = arp_entry->mac;
                memcpy(eth_h->ether_shost, eth_if->addr, 6); // modify the src mac to new interface
                memcpy(eth_h->ether_dhost, mac_tmp, 6); // modify the dest mac to next hop
                
                uint8_t* ip_payload = malloc(len - 34);
                memcpy(ip_payload, packet +ETH_HEADER_LENGTH+IP_HEADER_LENGTH, len - 34);
                
                uint8_t* new_packet = malloc(len);
                memcpy(new_packet, eth_h, ETH_HEADER_LENGTH);
                memcpy(new_packet + ETH_HEADER_LENGTH, ip_h, IP_HEADER_LENGTH);
                memcpy(new_packet + ETH_HEADER_LENGTH + IP_HEADER_LENGTH, ip_payload, len - 34);
                sr_send_packet(sr, new_packet, len, interface_new); // send to interface
                return;
            }
            else // can not find dst ip in arp entry cache
            {
                // send arp request
		printf("can't find dst mac in arp cache, send arp request\n"); 
                send_arp_request(sr, packet, len, interface, ip_dst);
                return;
            }
        }
    }
    // arp packet
    if(ntohs(eth_h->ether_type) == ethertype_arp)
    {
        printf("receive arp packet\n");
        sr_arp_hdr_t* arp_h = malloc(sizeof(sr_arp_hdr_t));
	memcpy(arp_h, packet + ETH_HEADER_LENGTH, ARP_HEADER_LENGTH);
        if(len - ETH_HEADER_LENGTH < ARP_HEADER_LENGTH) // packet is too short
        {
            fprintf (stderr, "Dropping arp packet. Too short. len: %d.\n", len);
            return;
        }
        if ((ntohs(arp_h->ar_pro) != ethertype_ip)
            || (ntohs(arp_h->ar_hrd) != arp_hrd_ethernet)
            || (arp_h->ar_pln != 4)
            || (arp_h->ar_hln != ETHER_ADDR_LEN))
        {
            /* Received unsupported packet argument */
            fprintf (stderr, "ARP packet received with invalid parameters. Dropping.\n");
            return;
        }
        
        if(ntohs(arp_h->ar_op) == arp_op_request) // if is arp request
        {
            printf("arp request\n");
	    if(arp_h->ar_tip == iface->ip) // asking for our ip
            {
		printf("%d\n",1);               
		sr_ethernet_hdr_t* eth_header = malloc(sizeof(sr_ethernet_hdr_t));
                memcpy(eth_header->ether_dhost, arp_h->ar_sha, ETHER_ADDR_LEN);
                memcpy(eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
                eth_header->ether_type = htons(ethertype_arp);
                
                sr_arp_hdr_t* arp_reply = malloc(sizeof(sr_arp_hdr_t));
                arp_reply->ar_hrd = htons(arp_hrd_ethernet);
                arp_reply->ar_pro = htons(ethertype_ip);
                arp_reply->ar_hln = ETHER_ADDR_LEN;
                arp_reply->ar_pln = 4;
                arp_reply->ar_op = htons(arp_op_reply);
                memcpy(arp_reply->ar_sha, iface->addr, ETHER_ADDR_LEN);
                arp_reply->ar_sip = iface->ip;
                memcpy(arp_reply->ar_tha, arp_h->ar_sha, ETHER_ADDR_LEN);
                arp_reply->ar_tip = arp_h->ar_sip;
                
                uint8_t* replypacket = malloc(ETH_HEADER_LENGTH + ARP_HEADER_LENGTH);
                memcpy(replypacket, eth_header, ETH_HEADER_LENGTH);
                memcpy(replypacket + ETH_HEADER_LENGTH, arp_reply, ARP_HEADER_LENGTH);
                sr_send_packet(sr, replypacket, ETH_HEADER_LENGTH + ARP_HEADER_LENGTH, iface->name);
            }
        }
        if(ntohs(arp_h->ar_op) == arp_op_reply) // if is arp reply
        {
	    printf("arp reply\n");
            if(arp_h->ar_tip == iface->ip) // reply to our arp request
            {
                struct sr_arpreq* requestPointer = sr_arpcache_insert(&sr->cache, arp_h->ar_sha, ntohl(arp_h->ar_tip));
                
                if (requestPointer != NULL)
                {
                    fprintf(stderr,"Received ARP reply, sending all queued packets.\n");
                
                    while (requestPointer->packets != NULL)
                    {
                        struct sr_packet* curr = requestPointer->packets;
                
                        /* Copy in the newly discovered Ethernet address of the frame */
                        memcpy(((sr_ethernet_hdr_t*) curr->buf)->ether_dhost,arp_h->ar_sha, ETHER_ADDR_LEN);
                
                        /* The last piece of the pie is now complete. Ship it. */
                        sr_send_packet(sr, curr->buf, curr->len, curr->iface);
                
                        /* Forward list of packets. */
                        requestPointer->packets = requestPointer->packets->next;
                
                        /* Free all memory associated with this packet (allocated on queue). */
                        //free(curr->buf);
                        //free(curr->iface);
                        //free(curr);
                    }
                                   
                    sr_arpreq_destroy(&sr->cache, requestPointer);
                }
                else
                {
                    /* Queued response to one of our ARP request retries? */
                    fprintf(stderr,"Received ARP reply, but found no request.\n");
                }
            }
        }
        else // unknown arp type
        {
            fprintf(stderr, "Unknown ARP TYPE. Dropping packet.\n");
            return;
        }
    }
    else // unknown packet type
    {
        fprintf(stderr, "Unknown ethertype: %d. Dropping packet.\n", ethertype(packet));
        return;
    }
    
}/* end sr_ForwardPacket */








