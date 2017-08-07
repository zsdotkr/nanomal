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

// ------------------------------------------------
// -------------------- decode --------------------
// ------------------------------------------------

typedef struct 
{	short	pos; 
	char	d[126]; 
} trc_t;

#define TRC_ADD(trc, fmt, y...) \
    {   (trc)->pos += snprintf(&(trc)->d[(trc)->pos], sizeof((trc)->d) - (trc)->pos, fmt " ", ##y); \
    }

typedef struct 
{	zl_ip_t			ip; 
	int				port;
} ip_port_t;

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

	int				vlan;
	
	ip_port_t		src, dest;

	int				proto;	// IPPROTO_TCP|UDP|...
	app_t			app; // APP_xxx
	union 
	{
		dec_tcp_t	tcp;
	};
} decode_t;

int decode_l4(decode_t* dec, const uint8_t* raw, int cap_len)
{	const uint8_t*	raw_org = raw;
	const uint8_t*	end = raw_org + cap_len;
	int				next_p; 	// next protocol

	dec->proto = 0;
	dec->app = APP_ERR;

	{	p_ether_t*	eh = (p_ether_t*)raw;
		raw += sizeof(*eh);
		THROW_L(ERR, raw > end, "too short L2");

		next_p = ntohs(eh->proto);
		if (next_p == ETHERTYPE_VLAN)
		{	p_vlan_t*	vh = (p_vlan_t*)raw; 
			raw += sizeof(*vh);
			THROW_L(ERR, raw > end, "too short VLAN");

			dec->vlan = ntohs(vh->vlan);
			TRC_ADD(&dec->trc, "VLAN:%d", dec->vlan);
			next_p = ntohs(vh->proto);
		}
		else
		{	dec->vlan = 0;	}
	}

	{	if (next_p == ETHERTYPE_ARP)
		{	p_arp_t*	ah = (p_arp_t*)raw; 
			raw += sizeof(*ah);
			THROW_L(ERR, raw > end, "too short ARP");
	
			zl_ip_set_ip4(&dec->src.ip, ntohl(ah->src_ip));
			zl_ip_set_ip4(&dec->dest.ip, ntohl(ah->dest_ip));

			dec->app = APP_ARP;

			return 0; 
		}
		else if (next_p == ETHERTYPE_IP)
		{	p_ip4_t*	iph = (p_ip4_t*)raw; 
			raw += sizeof (*iph);
			THROW_L(ERR, raw > end, "too short IP");
	
			zl_ip_set_ip4(&dec->src.ip, ntohl(iph->src)); 
			zl_ip_set_ip4(&dec->dest.ip, ntohl(iph->dest));
	
			next_p = iph->proto;
		}
		else if (next_p == ETHERTYPE_IPV6)	
		{	p_ip6_t*	iph = (p_ip6_t*)raw;
			raw += sizeof (*iph);
			THROW_L(ERR, raw > end, "too short IP6");
	
			zl_ip_set_ip6(&dec->src.ip, &iph->src); 
			zl_ip_set_ip6(&dec->dest.ip, &iph->dest);

			// TODO process optional header
	
			dec->app = APP_IP6;

			return 0;
		}
		else
		{	dec->app = APP_UNKNOWN;
			TRC_ADD(&dec->trc, "Unknwon family:%d", next_p);
			return 0; 
		}
	}

	{
		if (next_p == IPPROTO_ICMP)
		{	// TODO adjust payload
			dec->app = APP_ICMP; 
			dec->proto = IPPROTO_ICMP;
			TRC_ADD(&dec->trc, "ICMP");
			return 0;
		}	
		else if (next_p == IPPROTO_UDP)
		{	p_udp_t*	hdr = (p_udp_t*) raw; 
			raw += sizeof(*hdr);
			THROW_L(ERR, raw > end, "too short UDP");

			dec->proto = IPPROTO_UDP;
			dec->src.port = ntohs(hdr->src);
			dec->dest.port = ntohs(hdr->dest);

			dec->app = APP_UDP;
			TRC_ADD(&dec->trc, "UDP");
			return 0;
		}
		else if (next_p == IPPROTO_TCP)
		{	p_tcp_t* 	hdr = (p_tcp_t*)raw; 
			dec_tcp_t* 	dec_tcp = &dec->tcp; 

			raw += sizeof(*hdr);
			THROW_L(ERR, raw > end, "too short TCP");

			dec->proto = IPPROTO_TCP;
			dec->src.port = ntohs(hdr->src); 
			dec->dest.port = ntohs(hdr->dest); 
// ---
			dec_tcp->flag = hdr->flag;
			dec_tcp->seq = ntohl(hdr->seq);
			dec_tcp->ack = ntohl(hdr->ack_seq);
			dec_tcp->win = ntohs(hdr->window);
			dec_tcp->urg = ntohs(hdr->urg_ptr);
			TRC_ADD(&dec->trc, "S/A/W=%d/%d/%d", dec_tcp->seq, dec_tcp->ack, dec_tcp->win);

			dec_tcp->mss = 1460; 
			dec_tcp->use_sack = 0; 
			dec_tcp->win_scale = 0; 

			// save optional field
			if ((hdr->doff * 4) > sizeof(*hdr))
			{	int				remain = (hdr->doff * 4) - sizeof(*hdr);	
				p_tcp_opt_t*	opt; 

				for(; remain > 0; )
				{	opt = (p_tcp_opt_t*) raw; 
					switch (opt->type)
					{	case 2 : // MSS 
						dec_tcp->mss = ntohs(opt->d.d16);
						TRC_ADD(&dec->trc, "MSS:%d", dec_tcp->mss);
						break;
						case 4 : // SACK 
						dec_tcp->use_sack = 1;
						TRC_ADD(&dec->trc, "SACK");
						break;
						case 3 : // WINDOW SCALE
						dec_tcp->win_scale = opt->d.d8;
						TRC_ADD(&dec->trc, "WS:%d", dec_tcp->win_scale);
						break;
					}
					if (opt->type == 1)	// NOP
					{	raw += 1;	remain -= 1;	}
					else
					{	raw += opt->len; remain -= opt->len;	}
				}
			}
			dec->app = APP_TCP; 
			TRC_ADD(&dec->trc, "TCP");
			return 0;
		}
		else
		{	dec->app = APP_UNKNOWN; 	
			return 0;
		}
	}
	return 0; 

CATCH(ERR)
	return -1;
}

// ------------------------------------------------
// -------------------- flow ----------------------
// ------------------------------------------------

typedef struct 
{	struct 
	{	int64_t	byte, pkt; 	// out
		int64_t	byte_dup, pkt_dup;	// out 
	} lo, hi; 	
} traf_t;	// traffic 

typedef struct 
{	int				app;	// APP_xxx	
	struct flow_tcp_side_t
	{	ip_port_t	ip_port; 
		int			init_seq, init_win, init_mss, init_sack;
		int			last_ack;
		int			win_scale;	
	} low, hi; 

	char			client;	// 'l' (low), 'h' (high), 0x00 (unknown)
	char			step_open;	// TCP_F_SYN | ACK
	char			step_close;	// TCP_F_RST|FIN|ACK

	traf_t			traf_low, traf_hi;
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
	if (dec->src.ip.v4 < dec->dest.ip.v4)
	{	fkey->g.v4_l = dec->src.ip.v4; 
		fkey->g.v4_h = dec->dest.ip.v4; 
		fkey->u.port_l = dec->src.port;
		fkey->u.port_h = dec->dest.port;
	}
	else
	{	fkey->g.v4_l = dec->dest.ip.v4; 
		fkey->g.v4_h = dec->src.ip.v4; 
		fkey->u.port_l = dec->dest.port;
		fkey->u.port_h = dec->src.port;
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

void dump_flow_tcp(flow_tcp_t* flow)
{	struct flow_tcp_side_t* side[2];
	char			str1[64], str2[64]; 
	int		i; 

	LOG("-----------------------------------");
	LOG("client:%c, step_open:%x, step_close:%x", flow->client, flow->step_open, flow->step_close);
	if (flow->client == 'l')
	{	side[0] = &flow->low;	side[1] = &flow->hi;	}
	else
	{	side[0] = &flow->hi;	side[1] = &flow->low;	}

	sprintf(str1, "%s:%d", zl_ip_print(&side[0]->ip_port.ip), side[0]->ip_port.port);
	sprintf(str2, "%s:%d", zl_ip_print(&side[1]->ip_port.ip), side[1]->ip_port.port);
	LOG("IP    : %32s %32s", str1, str2);

	sprintf(str1, "%d/%d", side[0]->init_seq, side[0]->last_ack);
	sprintf(str2, "%d/%d", side[1]->init_seq, side[1]->last_ack);
	LOG("S/A   : %32s %32s", str1, str2);

	sprintf(str1, "%d/%d/%d", side[0]->init_win<<side[0]->win_scale, side[0]->init_mss, side[0]->init_sack);
	sprintf(str2, "%d/%d/%d", side[1]->init_win<<side[1]->win_scale, side[1]->init_mss, side[1]->init_sack);
	LOG("W/M/S  : %32s %32s", str1, str2);
	
}

void parse(struct pcap_pkthdr* hdr, const uint8_t* raw)
{	const uint8_t*	raw_org = raw; 	
	decode_t		dec; 
	int				len; 
	int				next;
	
	// initialize length
	memset(&dec, 0, sizeof(dec));
	dec.pkt_len = dec.payload_len = (hdr->len - g_dlt_offset);
	
	// adjust DLT header length 
	raw += g_dlt_offset; 	

	if (decode_l4(&dec, raw, hdr->caplen) < 0)
	{	ERR("%s %s:%d -> %s:%d %s", __func__, 
			zl_ip_print(&dec.src.ip), dec.src.port, 
			zl_ip_print(&dec.dest.ip), dec.dest.port, 
			dec.trc.d);
	}	
	LOG("%s %s:%d -> %s:%d %s", __func__, 
		zl_ip_print(&dec.src.ip), dec.src.port, 
		zl_ip_print(&dec.dest.ip), dec.dest.port, 
		dec.trc.d);


	if (dec.app == APP_TCP)
	{	flow_key_t	key; 
		flow_tcp_t*	flow; 
		int			exist;

		flow = flow_add(g_flow_list, flow_make_key(&key, &dec), sizeof(*flow), 1, &exist);
		if (exist == 0)	
		{	memset(flow, 0, sizeof(*flow));	

			flow->app = APP_TCP;
			// fill IP & Port
			if (dec.src.ip.v4 < dec.dest.ip.v4)
			{	flow->low.ip_port = dec.src;	flow->hi.ip_port = dec.dest; }
			else
			{	flow->low.ip_port = dec.dest;	flow->hi.ip_port = dec.src; }
			
			// determine side
			if ((dec.tcp.flag & TCP_F_SYN_ACK) == TCP_F_SYN)
			{	if (dec.src.ip.v4 < dec.dest.ip.v4)	{	flow->client = 'l'; }
				else								{	flow->client = 'h';	}
			}
			if ((dec.tcp.flag & TCP_F_SYN_ACK) == TCP_F_SYN_ACK)
			{	if (dec.src.ip.v4 < dec.dest.ip.v4) {	flow->client = 'h';	}
				else								{	flow->client = 'l';	}
			}
			else
			{	flow->client = 0;	}
		}

		if (dec.tcp.flag & TCP_F_SYN_ACK)
		{	if ((flow->step_open & TCP_F_SYN_ACK) != TCP_F_SYN_ACK)
			{	struct flow_tcp_side_t* side;
				if ((dec.tcp.flag & TCP_F_SYN_ACK) == TCP_F_SYN)				
				{	side = (flow->client == 'l') ? &flow->low : &flow->hi;	flow->step_open |= TCP_F_SYN;	}
				else
				{	side = (flow->client == 'l') ? &flow->hi : &flow->low; flow->step_open |= TCP_F_ACK;	}

				side->init_seq = dec.tcp.seq;
				side->init_win = dec.tcp.win; 
				side->init_mss = dec.tcp.mss; 
				side->init_sack = dec.tcp.use_sack;
				side->win_scale = dec.tcp.win_scale;
			}
			else	// duplicated SYN | SYN_ACK
			{	LOG("duplicated");
			}
		}
		dump_flow_tcp(flow);
	}
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
		{	parse(&pcap_hdr, pcap_raw);	
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







