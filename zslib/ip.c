#include "_zslib.h"

#define ZS_IP_MAGIC		0xfe7055aa	// may not be used for IPv6 address range

// ---------- internals --------------------

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

char* zl_ip_to_str(zl_ip_t* ptr, char* ret, int ret_len)
{	
	if (zl_ip_is_v4(ptr))
	{	uint32_t	v4 = htonl(ptr->v4);	
		inet_ntop(PF_INET, &v4, ret, ret_len);
	}		
	else	// ipv6
	{	inet_ntop(PF_INET6, &ptr->v6, ret, ret_len);
	}	
	return ret;
}

int	zl_ip_init()
{	
	return 0;
}

