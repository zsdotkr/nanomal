#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "decode.h"
#include "zslib.h"
#include "common.h"
/* ---------- override below 
 */

#define LOG(x,y...)		printf(x "\n", ##y)
#define ERR(x,y...)		printf("!! " x "\n", ##y)

/* ---------- global & static
 */

char		g_dev_name[128];	// network device name
char		g_filter_rule[128]; 
int			g_stat_intv;	
int			g_dlt_offset;		// pcap datalink header length

char*		g_flow_list;

typedef struct 
{	short	pos; 
	char	d[126]; 
} trc_t;

#define TRC_ADD(trc, fmt, y...) \
    {   (trc)->pos += snprintf(&(trc)->d[(trc)->pos], sizeof((trc)->d) - (trc)->pos, fmt " ", ##y); \
    }

typedef struct 
{	uint32_t			seq;
	uint32_t			ack;
	uint32_t			win; 
	int					urg;
	int					flag;	// TCP_FLAG_xxx	
	int					mss;	// SYN
	int					win_scale;	// SYN
	int					use_sack;		// SYN
} dec_tcp_t;
typedef struct 
{	trc_t			trc;	
	int				pkt_len;	// total length of packet
	int				payload_len;// payload (L5) length
	// L2 layer	
	int				vlan;
	// IP Layer 
	zl_ip_t			ip_src, ip_dest; 
	// L4 Layer - common
	int				proto; // IPPROTO_xxx
	int				port_src, port_dest; 

	dec_tcp_t*		tcp;
} decode_t;

// ---------- flow ---------------

typedef struct 
{	
	struct 
	{	zl_ip_t		ip; 
		int			port; 
		int			init_seq, init_ack, init_win;
		int			mss;
		int			sack;
		int			win_scale;
	} src, dest;
	int				ambiguous_src;
	int				step_open;		// TCP_F_SYN|SYN_ACK
	int				step_close;		// TCP_F_RST|FIN|FIN_ACK
} flow_tcp_t;

typedef struct 
{	union
	{	uint64_t		k; 
		struct 
		{	uint32_t	v4_l;		// lower side IPv4 
			uint32_t	v4_h;		// upper side IPv4
		} __attribute__ ((packed)); 
	} g;	
	union 
	{	uint64_t		k;
		struct 
		{	uint16_t	vlan; 	// VLAN id
			uint8_t		proto; 	// IPPROTO_xxx
			uint8_t		pad;	// 
			uint16_t	port_l; // port number of lower side IP
			uint16_t	port_h;	// port number of upper side IP
		} __attribute__ ((packed));
	} u;
} flow_key_t;

flow_key_t* flow_make_key(flow_key_t* fkey, decode_t* dec)
{	
	if (dec->ip_src.v4 < dec->ip_dest.v4)
	{	fkey->g.v4_l = dec->ip_src.v4; 
		fkey->g.v4_h = dec->ip_dest.v4; 
		fkey->u.port_l = dec->port_src;
		fkey->u.port_h = dec->port_dest;
	}
	else
	{	fkey->g.v4_l = dec->ip_dest.v4; 
		fkey->g.v4_h = dec->ip_src.v4; 
		fkey->u.port_l = dec->port_dest;
		fkey->u.port_h = dec->port_src;
	}
	fkey->u.vlan = dec->vlan;
	fkey->u.proto = dec->proto;
	fkey->u.pad = 0;

	return fkey;
}

void* flow_add(char* flow_list, flow_key_t* fkey, int size, int expire_at, int* exist)
{	void** 	ret; 

	ret = sklist_add(flow_list, fkey->g.k, fkey->u.k, expire_at); 
	THROW_L(ERR, ret == NULL, "malloc err(%d)", errno);

	if ((*ret) == NULL)
	{	(*ret) = malloc(size);
		THROW_L(CLR_ERR, (*ret) == NULL, "malloc2 err(%d)", errno);
		*exist = 0; 
	}
	else
	{	*exist = 1; 
	}

	LOG("%s, size:%d, already exist:%d", __func__, size, *exist);

	return *ret;

CATCH(ERR);
	return NULL;

CATCH(CLR_ERR);
	sklist_del_exact(flow_list, fkey->g.k, fkey->u.k);
	return NULL;
}

/* ---------- reporting
 */

void report_arp(decode_t* dec)
{	LOG("arp  : %x -> %x, %d/%d", dec->ip_src.v4, dec->ip_dest.v4, 
		dec->pkt_len, dec->payload_len);
}
void report_ipv6(decode_t* dec)
{	LOG("ipv6 : %x -> %x, %d/%d", dec->ip_src.v4, dec->ip_dest.v4, 
		dec->pkt_len, dec->payload_len);
}
void report_unknown_l3(decode_t* dec)
{	LOG("L2 ? : %x -> %x, %d/%d", dec->ip_src.v4, dec->ip_dest.v4, 
		dec->pkt_len, dec->payload_len);
}
void report_icmp(decode_t* dec)
{	LOG("ICMP : %x -> %x, %d/%d", dec->ip_src.v4, dec->ip_dest.v4, 
		dec->pkt_len, dec->payload_len);
}
void report_udp(decode_t* dec)
{	LOG("UDP  : %x:%d -> %x:%d, %d/%d", dec->ip_src.v4, dec->port_src, 
		dec->ip_dest.v4, dec->port_dest, 
		dec->pkt_len, dec->payload_len);
}
void report_tcp(decode_t* dec)
{	LOG("TCP  : %s:%d -> %s:%d, %d/%d %s", 
		zl_ip_print(&dec->ip_src), dec->port_src, 
		zl_ip_print(&dec->ip_dest), dec->port_dest, 
		dec->pkt_len, dec->payload_len, dec->trc.d);
}
void report_unknown_l4(decode_t* dec)
{	LOG("L3 %d : %x -> %x, %d/%d", dec->proto, dec->ip_src.v4,
		dec->ip_dest.v4, 
		dec->pkt_len, dec->payload_len);
}

/* ---------- parser 
 */

int decode_l4(decode_t* dec, int* next, const uint8_t* raw)
{	const uint8_t*	raw_org = raw; 
	int				proto = (*next);

	if (proto == IPPROTO_ICMP)
	{	// TODO adjust payload
		report_icmp(dec);
		return 0;
	}	
	else if (proto == IPPROTO_UDP)
	{	p_udp_t*	hdr = (p_udp_t*) raw; 
		raw += sizeof(*hdr);

		dec->proto = proto; 
		dec->port_src = ntohs(hdr->src);
		dec->port_dest = ntohs(hdr->dest);

		dec->payload_len -= (raw - raw_org);
		report_udp(dec);
		return 0;
	}
	else if (proto == IPPROTO_TCP)
	{	p_tcp_t* 	hdr = (p_tcp_t*)raw; 

		TRC_ADD(&dec->trc, "TCP");

		if ((dec->tcp = calloc(1, sizeof(dec_tcp_t))) == NULL)
		{	TRC_ADD(&dec->trc, "malloc err:%d", errno);
			return 0;
		}

		raw += sizeof(*hdr);

		dec->proto = proto; 
		dec->port_src = ntohs(hdr->src); 
		dec->port_dest = ntohs(hdr->dest); 

		dec->payload_len -= (raw - raw_org);

		// save mandatory field
		dec->tcp->flag = hdr->flag;
		dec->tcp->seq = ntohl(hdr->seq);
		dec->tcp->ack = ntohl(hdr->ack_seq);
		dec->tcp->win = ntohs(hdr->window);
		dec->tcp->urg = ntohs(hdr->urg_ptr);
		TRC_ADD(&dec->trc, "S/A/W=%d/%d/%d", dec->tcp->seq, dec->tcp->ack, dec->tcp->win);

		// save optional field
		if ((hdr->doff * 4) > sizeof(*hdr))
		{	int				remain = (hdr->doff * 4) - sizeof(*hdr);	
			p_tcp_opt_t*	opt; 

			for(; remain > 0; )
			{	opt = (p_tcp_opt_t*) raw; 
				switch (opt->type)
				{	case 2 : // MSS 
						dec->tcp->mss = ntohs(opt->d.d16);
						TRC_ADD(&dec->trc, "MSS:%d", dec->tcp->mss);
					break;
					case 4 : // SACK 
						dec->tcp->use_sack = 1;
						TRC_ADD(&dec->trc, "SACK");
					break;
					case 3 : // WINDOW SCALE
						dec->tcp->win_scale = 1 << opt->d.d8;
						TRC_ADD(&dec->trc, "WS:%d", dec->tcp->win_scale);
					break;
				}
				if (opt->type == 1)	// NOP
				{	raw += 1;	remain -= 1;	}
				else
				{	raw += opt->len; remain -= opt->len;	}
			}
		}

		{	flow_tcp_t*	flow; 
			flow_key_t	key; 
			int			exist; 
	
			flow = flow_add(g_flow_list, flow_make_key(&key, dec), sizeof(flow_tcp_t), 1, &exist);
			THROW(DROP, flow == NULL);
			
			if (exist == 0)	// init vars if newly added
			{	flow->ambiguous_src = 1; 	flow->step_open = flow->step_close = 0;	}

			if (dec->flag & TCP_F_SYN_ACK)
/* asd
			{	int		flag = dec->tcp->flag & (TCP_F_SYN | TCP_F_ACK);	

				if (flag == TCP_F_SYN)
				{	flow->ambiguous_src = 0;
					flow_step |= TCP_F_SYN;
					flow->ip_src = dec->ip_src;		flow->port_src = dec->port_src; 
					flow->ip_dest = dec->ip_dest;	flow->port_dest = dec->port_dest; 
				}
				if (flag == (TCP_F_SYN | TCP_F_ACK))
				{	flow->ip_src = dec->ip_dest;	flow->port_src = dec->port_dest; 
					flow->ip_dest = dec->ip_src;	flow->port_dest = dec->port_src; 
					flow->ambiguous_src = 0;
				}
			}
*/
			else
			{	LOG("exist");	}
		}

		// TODO check control & payload & any optional.. 
		report_tcp(dec);

		// decode_t p_tcp_t

		return 0;
	}
	else
	{	dec->proto = proto; 	
		report_unknown_l4(dec);
		return 0;
	}

CATCH(DROP);
	return -1;
}

int decode_l3(decode_t* dec, int* next, const uint8_t* raw)
{	const uint8_t* 	raw_org = raw; 
	int				family = (*next);	
 
	if (family == ETHERTYPE_ARP)
	{	p_arp_t*	ah = (p_arp_t*)raw; 
		raw += sizeof(*ah);
	
		zl_ip_set_ip4(&dec->ip_src, ntohl(ah->src_ip));
		zl_ip_set_ip4(&dec->ip_dest, ntohl(ah->dest_ip));

		dec->payload_len -= (raw - raw_org);
		report_arp(dec);
		
		return 0; 
	}
	else if (family == ETHERTYPE_IP)
	{	p_ip4_t*	iph = (p_ip4_t*)raw; 
		raw += sizeof (*iph);

		zl_ip_set_ip4(&dec->ip_src, ntohl(iph->src)); 
		zl_ip_set_ip4(&dec->ip_dest, ntohl(iph->dest));

		(*next) = iph->proto;

		return (raw - raw_org);
	}
	else if (family == ETHERTYPE_IPV6)	
	{	p_ip6_t*	iph = (p_ip6_t*)raw;
		raw += sizeof (*iph);

		zl_ip_set_ip6(&dec->ip_src, &iph->src); 
		zl_ip_set_ip6(&dec->ip_dest, &iph->dest);

		// TODO process optional header

		dec->payload_len -= (raw - raw_org);
		report_ipv6(dec);

		return 0;
	}
	else
	{	report_unknown_l3(dec);
		return 0;
	}	
}

int decode_l2(decode_t* dec, int* next, const uint8_t* raw)
{	const uint8_t*	raw_org = raw;	
	p_ether_t*		eh = (p_ether_t*)raw; 
	uint16_t		family;

	raw += sizeof(*eh);
	family = ntohs(eh->proto);

	// check VLAN
	if (family == ETHERTYPE_VLAN)
	{	p_vlan_t* vh = (p_vlan_t*)raw; 
		raw += sizeof(*vh);

		dec->vlan = ntohs(vh->vlan);
		TRC_ADD(&dec->trc, "VLAN:%d", dec->vlan);
		family = ntohs(vh->proto);
	}
	else
	{	dec->vlan = 0;	}

	(*next) = family;
	
	return raw - raw_org;
}

void decode_pkt(struct pcap_pkthdr* hdr, const uint8_t* raw)
{	const uint8_t*	raw_org = raw; 	
	decode_t		dec; 
	int				len; 
	int				next;
	
	// initialize length
	memset(&dec, 0, sizeof(dec));
	dec.pkt_len = dec.payload_len = (hdr->len - g_dlt_offset);
	
	// adjust DLT header length 
	raw += g_dlt_offset; 	

	// check VLAN & L2 header
	if ((len = decode_l2(&dec, &next, raw)) <= 0)
	{	return;	}

	raw += len; 
	dec.payload_len -= len; 

	// check L3 & IP layer
	if ((len = decode_l3(&dec, &next, raw)) <= 0)
	{	return;	}

	raw += len; 
	dec.payload_len -= len;
	decode_l4(&dec, &next, raw);
}

/* ---------- pcap related 
 */

pcap_t*	prepare_pcap(char* file, char* dev_name, char* filter, int snap_len, int read_to)
{	char				err[PCAP_ERRBUF_SIZE]; 
	pcap_t*				pc; 
	struct bpf_program	fp;
	int					ret;

	if (file[0] == 0)	// live
	{	pc = pcap_open_live(dev_name, snap_len, 1 /* promiscuous */, 
			read_to /* msec */, err); 
		THROW_L(ERR, pc == NULL, "open pcap err(%s)", err);
	}
	else
	{	pc = pcap_open_offline(file, err); 
		THROW_L(ERR, pc == NULL, "open file err(%s)", err);
	}
	
	if (strcasecmp(filter, "any") != 0)
	{		
		ret = pcap_compile(pc, &fp, filter, 0, PCAP_NETMASK_UNKNOWN); 
		THROW_L(CLOSE_ERR, ret < 0, "compile rule err(%s)", filter);
	
		ret = pcap_setfilter(pc, &fp);
		THROW_L(CLOSE_ERR, ret < 0, "set filter err(%s)", filter);
	}

	switch(pcap_datalink(pc))
	{	case 113: /*LINKTYPE_LINUX_SSL*/	g_dlt_offset = 2;	break; 
		case 1: /*LINKTYPE_ETHERNET*/		g_dlt_offset = 0;	break; 
		default: 
			LOG("Unknown DLT Type:%d", pcap_datalink(pc));
			g_dlt_offset = 0;
		break;
	}

	return pc;

CATCH(ERR);
	return NULL;
CATCH(CLOSE_ERR);
	pcap_close(pc); 
	return NULL;
}

/* ---------- main
 */

int disp_dev_list(int id, char* name)
{	pcap_if_t*	dev; 
	pcap_if_t*	cur;
	char		err[PCAP_ERRBUF_SIZE];
	char		out[128]; 
	char		ipbuf[128]; 
	int			pos, i;

	THROW_L(ERR, pcap_findalldevs (&dev, err) < 0, "no device (%s)", err);

	if (name == NULL)	{	LOG("Device List");	}

	for (cur = dev, i = 0; ; i++)
	{	if (cur == NULL)	{	break;	}

		if (name == NULL)
		{	pos = sprintf(out, "  * Device %d : %s", i, cur->name);

			if (cur->description)
			{	pos += sprintf(&out[pos], " (%s)",  cur->description);	}
	
			LOG("%s", out);
		}

		if (i == id)	
		{	strcpy(name, cur->name);	
			pcap_freealldevs(dev);
			return id;
		}
		cur = cur->next;
	}
	pcap_freealldevs(dev);
CATCH(ERR);
	return -1;

}

void disp_help()
{	LOG("Options");
	LOG("   -i number   : Network Device Number (default : %s, see Device List)", g_dev_name);
	LOG("   -R filter   : pcap filter rule (default : %s)", g_filter_rule);
	LOG("   -s interval : Statistics summary interval (default : %d sec)", g_stat_intv);
	LOG("   -f pcap     : load pcap file instead of live-capture");
}

int main(int argc, char* argv[])
{	pcap_t*			pc;	// pcap descriptor
	int64_t			total_read, cur_read;
	struct timeval	last_stat_time;
	char			pcap_file[128]; ;

	zl_init();

	// initialize options 
	strcpy(g_dev_name, "any");
	strcpy(g_filter_rule, "any");

	g_stat_intv = 60;	// every 1 min
	pcap_file[0] = 0;

	if (argc == 1)		{	disp_help();	disp_dev_list(-1, NULL);	return 0;	}

	// parse options 
	{	int		ch; 

		while ((ch = getopt(argc, argv, "hi:R:s:f:")) != EOF)
		{	switch (ch)
			{	case 'i': 
				{	int		id = atoi(optarg);
					if (disp_dev_list(id, g_dev_name) != id)
					{	LOG(" >> Invalid Device Number : %d", id);
						return -1;
					}
				}
				break;
				case 'R':
				{	strcpy(g_filter_rule, optarg);	}
				break;
				case 's':
				{	g_stat_intv = atoi(optarg);	}
				break;
				case 'f': 
				{	strcpy(pcap_file, optarg);	}
				break;
				case 'h':
				{	disp_help();	disp_dev_list(-1, NULL);    return 0;	}
				break;
				default: 
				{	disp_help(); 	disp_dev_list(-1, NULL);
					return -1;
				}
			}
		}	
	}

	// summary options 
	LOG("Run Options");
	LOG("  * Device Name         : %s", g_dev_name);
	LOG("  * Filter              : %s", g_filter_rule);
	LOG("  * Statistics Interval : %d [sec]", g_stat_intv);
	if (pcap_file[0])
	{	LOG("  * PCAP File           : %s", pcap_file);	}

	// prepare pcap
	if ((pc = prepare_pcap(pcap_file, g_dev_name, g_filter_rule, 128, 100)) == NULL)
	{	return -1;	}

	LOG("Start");

	last_stat_time.tv_sec = 0; 
	last_stat_time.tv_usec = 0; 

	g_flow_list = sklist_create(0);

	for(cur_read = 0, total_read = 0; total_read < 10;)
	{	const u_char*		pcap_raw; // raw packet data 
		struct pcap_pkthdr	pcap_hdr;

		if ((pcap_raw = pcap_next(pc, &pcap_hdr)) != NULL)
		{	decode_pkt(&pcap_hdr, pcap_raw);	
			total_read++;	cur_read++;
		}
		else	// get system time if read timeout
		{	gettimeofday(&pcap_hdr.ts, NULL);
		}
		
		if ((pcap_hdr.ts.tv_sec % g_stat_intv) == 0)
		{	if (pcap_hdr.ts.tv_sec != last_stat_time.tv_sec) 
			{	struct pcap_stat	ps; 	
				struct tm			date; 
				char				timebuf[128]; 
				char				out[256]; 
				int					olen;

				// get time string
				localtime_r(&pcap_hdr.ts.tv_sec, &date);
				strftime(timebuf, 128, "%d %T", &date);

				olen = sprintf(out, "Process %zd %zd", total_read, cur_read);
				
				// get pcap stat
				if (pcap_stats(pc, &ps) >= 0)
				{	olen += sprintf(&out[olen], " drop %u if_drop %u", 
								ps.ps_drop, ps.ps_ifdrop);
				}
				
				LOG("%s %s", timebuf, out);

				last_stat_time.tv_sec = pcap_hdr.ts.tv_sec;
				cur_read = 0;
			}
		}
	}		
	LOG("End");
	pcap_close(pc);

	return 0;
}







