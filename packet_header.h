#ifndef __PACKET_HEADER_H__
#define __PACKET_HEADER_H__

typedef struct eth_hdr {
    unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
    unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
    uint16_t        h_proto;                /* packet type ID field */
} __attribute__ ((packed)) ether_t;

typedef struct vlan_hdr {
    uint16_t       vlan_id;              /* Tag Control Information (QoS, VLAN ID) */
    uint16_t       proto;                /* packet type ID field */
} __attribute__ ((packed)) ether_vlan_t;

typedef struct arp_hdr
{
    uint16_t h_type;
    uint16_t p_type;
    uint8_t h_size;
    uint8_t p_size;
    uint16_t opcode;
    unsigned char source_mac[6];
    uint32_t source_ip;
    unsigned char target_mac[6];
    uint32_t target_ip;
} __attribute__ ((packed)) arp_t;


typedef struct iphdr_t {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t   ihl:4,
	version:4;
#else
    uint8_t   version:4,
              ihl:4;
#endif
    uint8_t   tos;
    uint16_t  tot_len;
    uint16_t  id;
#define IP_CE       0x8000
#define IP_DF       0x4000
#define IP_MF       0x2000
#define IP_OFFSET   0x1FFF
    uint16_t  frag_off;
    uint8_t   ttl;
    uint8_t   protocol;
    uint16_t  check;
    uint32_t  saddr;
    uint32_t  daddr;
    /*The options start here. */
} __attribute__ ((packed)) iphdr_t;

typedef struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t         priority:4,
                    version:4;
#else
    uint8_t         version:4,
                    priority:4;
#endif
    uint8_t         flow_lbl[3];

    uint16_t        payload_len;
    uint8_t         nexthdr;
    uint8_t         hop_limit;

    struct in6_addr saddr;
    struct in6_addr daddr;
} __attribute__ ((packed)) ipv6hdr_t;

typedef struct {
    uint8_t     nexthdr;
    uint8_t     hdrlen;
    /* TLV encoded option data follows */
} __attribute__((packed)) ipv6opt_hdr_t;


typedef struct {
    uint16_t    source;
    uint16_t    dest;
    uint16_t    len;
    uint16_t    check;
} __attribute__ ((packed)) udphdr_t;

typedef struct {
    uint16_t  source;
    uint16_t  dest;
    uint32_t  seq;
    uint32_t  ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t	  res1:4; 
	uint8_t	  doff:4;
#else
	uint8_t	  doff:4;
	uint8_t	  res1:4; 
#endif
	uint8_t   flag;
	#define TCP_FLAG_FIN	0x01
	#define TCP_FLAG_SYN	0x02
	#define TCP_FLAG_RST	0x04
	#define TCP_FLAG_PSH	0x08
	#define TCP_FLAG_ACK	0x10
	#define TCP_FLAG_URG	0x20
	#define TCP_FLAG_ECN	0x40
	#define TCP_FLAG_CWR	0x80
/*
#if __BYTE_ORDER == __LITTLE_ENDIAN
	
    uint16_t  res1:4,
              doff:4,
              fin:1,
              syn:1,
              rst:1,
              psh:1,
              ack:1,
              urg:1,
              ece:1,
              cwr:1;
#else
    uint16_t  doff:4,
              res1:4,
              cwr:1,
              ece:1,
              urg:1,
              ack:1,
              psh:1,
              rst:1,
              syn:1,
              fin:1;
#endif
*/
    uint16_t  window;
    uint16_t  check;
    uint16_t  urg_ptr;
} __attribute__ ((packed)) tcphdr_t;


typedef struct 
{	uint8_t		type; 
	uint8_t		len; 
	union 
	{	uint8_t		d8; 
		uint16_t	d16;		
		uint32_t	d32;
	} d;
} __attribute__ ((packed)) tcpopthdr_t;

#endif
