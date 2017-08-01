#include "_zslib.h"

#define ZS_IP_MAGIC		0xfe7055aa	// may not be used for IPv6 address range

// ---------- internals --------------------

#define _MAX_ARY	64 // must be 2^n
typedef struct 
{	int		head; 
	char	data[_MAX_ARY][45]; // 0000:1111:2222:3333:4444:5555:6666:7777:8888
} tricky_t;

static tricky_t	ipstr_buf; 

static char* _get_ipstr_buf()
{	int		pos; 
	pos = atomic_fetch_and_add(&ipstr_buf.head, 1);
	pos &= (_MAX_ARY - 1); 
	atomic_fetch_and_and(&ipstr_buf.head, _MAX_ARY-1);
	return ipstr_buf.data[pos]; 	
}

// ---------- externals --------------------
int zl_ip_is_v4(zl_ip_t* ptr)
{	return (ptr->flag == htonl(ZS_IP_MAGIC));
}

void zl_ip_set_ip4(zl_ip_t* ptr, uint32_t ip)
{	memset(ptr, 0, sizeof(*ptr));
	ptr->v4 = ip; 
	ptr->flag = htonl(ZS_IP_MAGIC);
}

void zl_ip_set_ip6(zl_ip_t* ptr, void* ip)
{	memcpy(ptr, ip, sizeof(*ptr));
}

const char* zl_ip_to_str(zl_ip_t* ptr)
{	char*	data = _get_ipstr_buf(); 
	if (zl_ip_is_v4(ptr))
	{	uint32_t	v4 = htonl(ptr->v4);	
		inet_ntop(PF_INET, &v4, data, sizeof(ipstr_buf.data[0]));
	}		
	else	// ipv6
	{	inet_ntop(PF_INET6, &ptr->v6, data, sizeof(ipstr_buf.data[0]));
	}	
	return data;
}

int	zl_ip_init()
{	memset(&ipstr_buf, 0, sizeof(ipstr_buf));
	return 0;
}

