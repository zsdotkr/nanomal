#ifndef __PACKET_HEADER_H__
#define __PACKET_HEADER_H__

#ifndef ETH_ALEN
	#define ETH_ALEN	6
#endif

typedef struct p_ether_t {
	uint8_t			dest[ETH_ALEN];       
	uint8_t			src[ETH_ALEN];     
	uint16_t		proto;                
} __attribute__ ((packed)) p_ether_t; // ethernet packet header

typedef struct p_vlan_t {
	uint16_t		vlan;
	uint16_t		proto;                
} __attribute__ ((packed)) p_vlan_t;	// vlan packet header

typedef struct p_arp_t {
	uint16_t		h_type;
	uint16_t		p_type;
	uint8_t			h_size;
	uint8_t			p_size;
	uint16_t		opcode;
	uint8_t			src_mac[ETH_ALEN];
	uint32_t		src_ip;
	uint8_t			dest_mac[ETH_ALEN];
	uint32_t		dest_ip;
} __attribute__ ((packed)) p_arp_t;

typedef struct p_ip4_t {
	#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint8_t			ihl:4,
						ver:4;
	#else
		uint8_t			ver:4,
						ihl:4;
	#endif

	uint8_t			tos;
	uint16_t		tot_len;
	uint16_t		id;
	#define IP_CE       0x8000
	#define IP_DF       0x4000
	#define IP_MF       0x2000
	#define IP_OFFSET   0x1FFF

	uint16_t		frag_off;
	uint8_t			ttl;
	uint8_t			protocol;
	uint16_t		check;
	uint32_t		src;
	uint32_t		dest;
	// Option header start from here
} __attribute__ ((packed)) p_ip4_t;

typedef struct p_ip6_t {
	#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint8_t		prio:4,	// priority
					ver:4;	// version
	#else
		uint8_t		ver:4,
					prio:4;
	#endif

	uint8_t			flow_lbl[3];
	
	uint16_t		payload_len;
	uint8_t			nexthdr;
	uint8_t			hop_limit;
	
	uint8_t			src[16]; 
	uint8_t			dest[16]; 
} __attribute__ ((packed)) p_ip6_t;

typedef struct p_ip6_opt_t {
	uint8_t			nexthdr;
	uint8_t			hdrlen;
	// TLV encoded option data follows 
} __attribute__((packed)) p_ip6_opt_t;

typedef struct p_udp_t {
	uint16_t		src;
	uint16_t		dest;
	uint16_t		len;
	uint16_t		check;
} __attribute__ ((packed)) p_udp_t;

typedef struct p_tcp_t {
	uint16_t		src;
	uint16_t		dest;
	uint32_t		seq;
	uint32_t		ack_seq;

	#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint8_t		res1:4, 
					doff:4;
	#else
		uint8_t		doff:4,
					res1:4; 
	#endif

	uint8_t			flag;	// see TCP_FLAG_xxx
	#define TCP_FLAG_FIN	0x01
	#define TCP_FLAG_SYN	0x02
	#define TCP_FLAG_RST	0x04
	#define TCP_FLAG_PSH	0x08
	#define TCP_FLAG_ACK	0x10
	#define TCP_FLAG_URG	0x20
	#define TCP_FLAG_ECN	0x40
	#define TCP_FLAG_CWR	0x80

	uint16_t		window;
	uint16_t		check;
	uint16_t		urg_ptr;
} __attribute__ ((packed)) p_tcp_t;

typedef struct p_tcp_opt_t {
	uint8_t			type; 
	uint8_t			len; 
	union 
	{	uint8_t		d8; 
		uint16_t	d16;		
		uint32_t	d32;
	} d;
} __attribute__ ((packed)) p_tcp_opt_t;

#endif
