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
#define DBG(x,y...)		printf(" * " x "\n", ##y)
#define ERR(x,y...)		printf("!! " x "\n", ##y)

/* ---------- global & static
 */

char		g_dev_name[128];	// network device name
char		g_filter_rule[128]; 
int			g_stat_intv;	
int			g_dlt_offset;		// pcap datalink header length

char*		g_flow_list;
int			g_pkt_id; 	// debugging 

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
#define TRC_INIT(trc)	{	(trc)->pos = 0; (trc)->d[0] = 0;	}

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
	int					mss;		// Option
	int					win_scale;	// Option
	int					use_sack;	// Option
} dec_tcp_t;

typedef struct 
{	trc_t			trc;	
	trc_t			trc_o;	
	int				pkt_len;	// total length of packet
	int				payload_len;// payload (L5) length
	int				pad_len;	

	int				vlan;
	
	ip_port_t		src, dest;

	int				proto;	// IPPROTO_TCP|UDP|...
	app_t			app; // APP_xxx
	union 
	{
		dec_tcp_t	tcp;
	};
} decode_t;

char* tcp_flag_to_str(int flag, char* ret)
{	
	ret[0] = (flag & TCP_F_SYN) ? 'S' : '.' ; 
	ret[1] = (flag & TCP_F_ACK) ? 'A' : '.' ; 
	ret[2] = (flag & TCP_F_PSH) ? 'P' : '.' ; 
	ret[3] = (flag & TCP_F_FIN) ? 'F' : '.' ; 
	ret[4] = (flag & TCP_F_RST) ? 'R' : '.' ; 
	ret[5] = (flag & TCP_F_URG) ? 'U' : '.' ; 
	ret[6] = (flag & TCP_F_ECN) ? 'E' : '.' ; 
	ret[7] = (flag & TCP_F_CWR) ? 'C' : '.' ; 
	ret[8] = 0;
	
	return ret;
}
#define tcp_flag_print(x)	tcp_flag_to_str(x, alloca(10))

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

			dec->payload_len = ntohs(iph->tot_len) - sizeof(*iph);
	
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

			TRC_ADD(&dec->trc, "TCP");

			dec->proto = IPPROTO_TCP;
			dec->src.port = ntohs(hdr->src); 
			dec->dest.port = ntohs(hdr->dest); 
// ---
			dec_tcp->flag = hdr->flag;
			dec_tcp->seq = ntohl(hdr->seq);
			dec_tcp->ack = ntohl(hdr->ack_seq);
			dec_tcp->win = ntohs(hdr->window);
			dec_tcp->urg = ntohs(hdr->urg_ptr);
			TRC_ADD(&dec->trc, "[%s]", tcp_flag_print(dec_tcp->flag));
			TRC_ADD(&dec->trc_o, "S/A=%d/%d", dec_tcp->seq % 10000, dec_tcp->ack % 10000);
			TRC_ADD(&dec->trc_o, "W:%d", dec_tcp->win);
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
						TRC_ADD(&dec->trc_o, "MSS:%d", dec_tcp->mss);
						break;
						case 4 : // SACK 
						dec_tcp->use_sack = 1;
						TRC_ADD(&dec->trc_o, "SACK");
						break;
						case 3 : // WINDOW SCALE
						dec_tcp->win_scale = opt->d.d8;
						TRC_ADD(&dec->trc_o, "WS:%d", dec_tcp->win_scale);
						break;
					}
					if (opt->type == 1)	// NOP
					{	raw += 1;	remain -= 1;	}
					else
					{	raw += opt->len; remain -= opt->len;	}
				}
			}
			dec->payload_len -= (raw - (uint8_t*)hdr);
			TRC_ADD(&dec->trc, "[%d]", dec->payload_len);
			dec->app = APP_TCP; 
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

// from wireshark GT_SEQ, ...
#define GT_SEQ(x, y)	((int)((y) - (x)) < 0)	// 1 : x > y, 0 : else
#define GE_SEQ(x, y)	((int)((y) - (y)) <= 0)	// 1 : x >= y, 0 : else
#define LT_SEQ(x, y)	((int)((x) - (y)) < 0)	// 1 : x < y, 0 : else
#define LE_SEQ(x, y)	((int)((x) - (y)) <= 0)	// 1 : x <= y, 0 : else
#define SN(x)			((x) % 10000)

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
		uint32_t	init_seq, init_win, init_mss, init_sack;

		uint32_t	seq_n; 	// next sequence
		uint32_t	seq_a; /// sequence acked
		uint32_t	win;
		int			inflight;

		int			win_scale;	

	} low, hi; 

	char			client;	// 'l' (low), 'h' (high), 0x00 (unknown)
	char			setup_open;	// TCP_SETUP_xxx
	#define TCP_SETUP_SYN			1
	#define TCP_SETUP_SYN_ACK		2
	#define TCP_SETUP_SEQ			4

	char			closer;	// 'l' or 'h'
	char			setup_close;	// TODO RST|FIN|ACK
	#define TCP_SWETUP_FIN			1
	#define TCP_SETUP_FIN_ACK		2
	#define TCP_SETUP_FIN_ACK_ACK	4

	int				evt;			// TCP_EVT_xxx
	#define TCP_EVT_ZERO_WIN		1
	#define TCP_EVT_ZERO_WIN_PROBE	2

	traf_t			traf_low, traf_hi;
	// trc_t			trc_l, trc_r;
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
		DBG("%s, create new size:%d", __func__, size);
	}
	else
	{	*exist = 1; 
	}


	return *ret;

CATCH(ERR);
	return NULL;

CATCH(CLR_ERR);
	sklist_del_exact(flow_list, fkey->g.k, fkey->u.k);
	return NULL;
}

void dump_flow_tcp(flow_tcp_t* flow, int opt)
{
	struct flow_tcp_side_t* cl; 	// client
	struct flow_tcp_side_t* sv; 	// server
	
	char			str1[64], str2[64]; 
	int		i; 


	if (flow->client == 'l')
	{	cl = &flow->low;	sv = &flow->hi;	}
	else
	{	cl = &flow->hi;	sv = &flow->low;	}

	if (opt & 0x01)
	{	DBG("client:%c, setup_open:%x, setup_close:%x", flow->client, flow->setup_open, flow->setup_close);

		sprintf(str1, "%s:%d", zl_ip_print(&cl->ip_port.ip), cl->ip_port.port);
		sprintf(str2, "%s:%d", zl_ip_print(&sv->ip_port.ip), sv->ip_port.port);
		DBG("IP        : %32s %32s", str1, str2);

		sprintf(str1, "%d/%d/%d", cl->init_win<<cl->win_scale, cl->init_mss, cl->init_sack);
		sprintf(str2, "%d/%d/%d", sv->init_win<<sv->win_scale, sv->init_mss, sv->init_sack);
		DBG("W/M/SACK  : %32s %32s", str1, str2);
	}
	if (opt & 0x02)
	{	sprintf(str1, "%d/%d/%d", 
			SN(cl->seq_n), SN(cl->seq_a), SN(cl->init_seq));
		sprintf(str2, "%d/%d/%d", 
			SN(sv->seq_n), SN(sv->seq_a), SN(sv->init_seq));
		DBG("SEQ N/A/I : %32s %32s", str1, str2);

		sprintf(str1, "%d / %d", cl->inflight, cl->win);
		sprintf(str2, "%d / %d", sv->inflight, sv->win);
		DBG("F/W       : %32s %32s", str1, str2);
	}
}

int parse_tcp(decode_t* dec)
{	dec_tcp_t*	dtcp = &dec->tcp;
	flow_tcp_t*	flow; 
	struct flow_tcp_side_t	*my, *peer;
	trc_t*		trc_lr;
	trc_t		trc_d, trc_l, trc_r;

	TRC_INIT(&trc_l); TRC_INIT(&trc_r);	TRC_INIT(&trc_d);

	// get flow
	{	flow_key_t	key; 
		int			exist;

		flow = flow_add(g_flow_list, flow_make_key(&key, dec), sizeof(*flow), 1, &exist);
		if (exist == 0)	
		{	memset(flow, 0, sizeof(*flow));	

			flow->app = APP_TCP;
			// fill IP & Port
			if (dec->src.ip.v4 < dec->dest.ip.v4)
			{	flow->low.ip_port = dec->src;	flow->hi.ip_port = dec->dest; }
			else
			{	flow->low.ip_port = dec->dest;	flow->hi.ip_port = dec->src; }
	
			// determine side
			if ((dtcp->flag & TCP_F_SYN_ACK) == TCP_F_SYN)
			{	if (dec->src.ip.v4 < dec->dest.ip.v4)	{	flow->client = 'l'; }
				else								{	flow->client = 'h';	}
			}
			else if ((dtcp->flag & TCP_F_SYN_ACK) == TCP_F_SYN_ACK)
			{	if (dec->src.ip.v4 < dec->dest.ip.v4) {	flow->client = 'h';	}
				else								{	flow->client = 'l';	}
			}
			else
			{	flow->client = 'l';	}
			TRC_ADD(&trc_d, "NEW");
		}
	}

	TRC_ADD(&trc_l, "%3d [T", g_pkt_id);
	if (flow->client == 'l')
	{	if (memcmp(&dec->src.ip, &flow->low.ip_port.ip, sizeof(dec->src.ip)) == 0)
		{	TRC_ADD(&trc_l, "%d/%d]", flow->low.ip_port.port, flow->hi.ip_port.port);	
			// TRC_ADD(&flow->trc_c, "C > S");
			trc_lr = &trc_l;
		}
		else
		{	TRC_ADD(&trc_l, "%d/%d]", flow->hi.ip_port.port, flow->low.ip_port.port);	
			// TRC_ADD(&flow->trc_c, "S > C");
			trc_lr = &trc_r;
		}
	}	
	else
	{	if (memcmp(&dec->src.ip, &flow->hi.ip_port.ip, sizeof(dec->src.ip)) == 0)
		{	TRC_ADD(&trc_l, "%d/%d]", flow->hi.ip_port.port, flow->low.ip_port.port);	
			// TRC_ADD(&flow->trc_c, "C > S");
			trc_lr = &trc_l;
		}
		else
		{	TRC_ADD(&trc_l, "%d/%d]", flow->low.ip_port.port, flow->hi.ip_port.port);	
			// TRC_ADD(&flow->trc_c, "S > C");
			trc_lr = &trc_r;
		}
	}
	TRC_ADD(&trc_l, "%s", tcp_flag_print(dtcp->flag));

	// get my & peer flow 
	if (dec->src.ip.v4 < dec->dest.ip.v4)	{	my = &flow->low;	peer = &flow->hi;	}
	else									{	my = &flow->hi;		peer = &flow->low;	}

	// setup sequence 
	if ((flow->setup_open & TCP_SETUP_SEQ) == 0)
	{	if ((dtcp->flag & TCP_F_SYN_ACK) == TCP_F_SYN)
		{	if ((flow->setup_open & TCP_SETUP_SYN) == TCP_SETUP_SYN)
			{	DBG("already TCP_SYN");	// TODO
				return 0;
			}
			else
			{	my->init_win = dtcp->win; 
				my->init_mss = dtcp->mss; 
				my->init_sack = dtcp->use_sack;
				my->win_scale = dtcp->win_scale;
				my->inflight = 1;

				my->init_seq = dtcp->seq; 
				my->seq_n = dtcp->seq+1; 
				my->seq_a = dtcp->seq;
				flow->setup_open |= TCP_SETUP_SYN;
			}
		}
		else if ((dtcp->flag & TCP_F_SYN_ACK) == TCP_F_SYN_ACK)
		{	if ((flow->setup_open & TCP_SETUP_SYN_ACK) == TCP_SETUP_SYN_ACK)
			{	DBG("already SYN_ACK");	// TODO
				return 0;
			}
			else
			{	flow->setup_open |= TCP_SETUP_SYN_ACK;
				
				my->init_win = dtcp->win; 
				my->init_mss = dtcp->mss; 
				my->init_sack = dtcp->use_sack;
				my->win_scale = dtcp->win_scale;
				my->inflight = 1;

				my->init_seq = dtcp->seq; 
				my->seq_n = dtcp->seq + 1; // ?? 
				my->seq_a = dtcp->seq;

				flow->setup_open |= TCP_SETUP_SEQ;
				TRC_ADD(&trc_d, "FIX");
			}
		}
		else
		{	
			my->init_seq = dtcp->seq;
			my->seq_n = my->init_seq+1; 
			my->seq_a = my->init_seq;

			peer->init_seq = dtcp->ack-1; 
			peer->seq_n = peer->init_seq+1; 
			peer->seq_a = peer->init_seq;

			flow->setup_open |= TCP_SETUP_SEQ;
			TRC_ADD(&trc_d, "FIX");
		}
	}

	// update window
	my->win = dtcp->win << my->win_scale;

	TRC_ADD(trc_lr, "S:%d A:%d W:%d [%d]", dtcp->seq - my->init_seq, dtcp->ack - peer->init_seq, 
		my->win, dec->payload_len);

	// update seq_n 
	if (dec->payload_len)	// TODO ?? 
	{	if (LT_SEQ(dtcp->seq, my->seq_n))
		{	TRC_ADD(&trc_d, "retransmit ??");	}
		else if (dtcp->seq == my->seq_n)
		{	my->seq_n += dec->payload_len;
			my->inflight += dec->payload_len;
		}
		else
		{	TRC_ADD(&trc_d, "packet lost ??, adjust");
			my->seq_n = dtcp->seq;
			my->inflight =  my->seq_n - my->seq_a;	
		}
	}

	// process FIN
	if (dtcp->flag & TCP_F_FIN)
	{	if (flow->closer == 0)	// if first close
		{	// here	
		}	
	}

	// process ACK 
	if (dtcp->flag & TCP_F_ACK)
	{	if (GT_SEQ(dtcp->ack, peer->seq_n))
		{	
			TRC_ADD(&trc_d, "packet lost ??");	// TODO
		}
		else if (GE_SEQ(dtcp->ack, peer->seq_a))
		{	int	diff = dtcp->ack - peer->seq_a;
			peer->inflight -= diff; 
			peer->seq_a = dtcp->ack;
		}
		else	// dtcp->ack <= peer->seq_a
		{	TRC_ADD(&trc_d, "duplicated ack??");
		}
		// dump_flow_tcp(flow, 2);
	}

	LOG("%-55s %c %s %s %s", trc_l.d, (trc_lr == &trc_l) ? '>' : '<', trc_r.d, 
		(trc_d.d[0]) ? "##" : "", trc_d.d);
/*
	// zero window
	if (my->win == 0)	
	{	flow->evt |= TCP_EVT_ZERO_WIN;	DBG("Zero Window");	}

	// zero window probing
	if ((dec->payload_len == 1) && (dec->tcp.seq == my->seq_n) && 
			(my->win == 0))
	{	flow->evt |= TCP_EVT_ZERO_WIN_PROBE;	DBG("Zero Window Probing");	}

	// LOST PACKET


	// check ack 
	if (dec->tcp.flag & TCP_F_ACK)
	{		
		if ((flow->setup_open & TCP_SETUP_SEQ) == 0)
		{	my->init_seq = dec->tcp.seq - 1;	
			peer->init_seq = dec->tcp.ack -1;
			flow->setup_open |= TCP_SETUP_SEQ;
		}	

		// see wireshark/epan/dissector/packet-tcp.c/tcp_analyze_sequence_number



	}
	// dump_flow_tcp(flow);

*/
	return 0;
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
/*
	LOG("%2d) %d > %d %s %s [%s %s]", id++, 
		dec.src.port, dec.dest.port, 
		dec.trc.d, dec.trc_o.d, 
		zl_ip_print(&dec.src.ip), 
		zl_ip_print(&dec.dest.ip));
*/		

	g_pkt_id++;

	if (dec.app == APP_TCP)
	{	parse_tcp(&dec);	}

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

	for(cur_read = 0, total_read = 0; total_read < 30;)
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
				
				// LOG("%s %s", timebuf, out);

				last_stat_time.tv_sec = pcap_hdr.ts.tv_sec;
				cur_read = 0;
			}
		}
	}		
	LOG("End (total %zd pkts)", total_read);
	pcap_close(pc);

	return 0;
}







