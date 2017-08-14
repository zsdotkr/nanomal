#include "_zslib.h"

#define ZS_IP_MAGIC		0xfe7055aa	// may not be used for IPv6 address range

// ---------- internals --------------------

// ---------- externals --------------------
int zl_ip_is_private(zl_ip_t* ptr)
{	if (ptr->flag == htonl(ZS_IP_MAGIC))	// v4
	{	if (((ptr->v4 & 0xff000000) == 0x0a000000) || 	// if 10.x.x.x
			((ptr->v4 & 0xfff00000)	== 0xac100000) || 	// if 172.16 ~ 172.31
			((ptr->v4 & 0xffff0000) == 0xc0a80000) ||	// if 192.168.x.x
			((ptr->v4 & 0xffc00000) == 0x64400000))		// if 100.64 ~ 100.127 (CGNAT)
		{	return 1;	}

		return 0;	
	}
	else // v6
	{	if ((ptr->v6[0] & 0xfe) == 0xfc)	// if fc00::/7 ULA
		{	return 1;	}

		return 0;
	}
}

int zl_ip_is_v4(zl_ip_t* ptr)
{	return (ptr->flag == htonl(ZS_IP_MAGIC));
}

void zl_ip_set_ip4(zl_ip_t* ptr, uint32_t ip)
{	ptr->flag = htonl(ZS_IP_MAGIC);
	ptr->dmy[1] = ptr->dmy[2] = 0;
	ptr->v4 = ip; 
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

