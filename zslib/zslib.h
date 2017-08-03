#ifndef __ZSLIB_H__
#define __ZSLIB_H__

// ---------- global includes --------------------

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <search.h>
#include <linux/unistd.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <dirent.h>
#include <syslog.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/msg.h>
#include <sys/ipc.h>

// ---------- global macros --------------------
#ifndef offsetof
	#define offsetof(type,member)	(int)(__builtin_offsetof(type, member))
#endif
#ifndef sizeofst
	#define sizeofst(x,y)			(int)(sizeof(x)/sizeof(y))
#endif
#ifndef likely
	#define likely(x)				__builtin_expect(!!(x),1)
	#define unlikely(x)				__builtin_expect(!!(x),0)
#endif

// ---------- atomic operations --------------------

#define atomic_compare_and_swap(ptr, old, new) 	__sync_bool_compare_and_swap(ptr, old, new)
#define atomic_fetch_and_add(ptr, inc)			__sync_fetch_and_add(ptr, inc)
#define atomic_fetch_and_and(ptr, val)			__sync_fetch_and_and(ptr, val)
#define atomic_zero(ptr)						__sync_fetch_and_and(ptr, 0)

// ---------- global structures --------------------

typedef union 
{	uint32_t	flag;	
	#define 	ZS_IP4	0xfe7055aa // FE04::/10 may not used within IPv6 address range

	uint8_t		v6[16]; 
	struct 
	{	uint32_t	dmy[3];
		uint32_t	v4;			// host endian 
	};
} zl_ip_t;	// host endian IP storage structure

// ---------- prototypes ---------------------------

// ip.c
int			zl_ip_is_v4(zl_ip_t* ptr);
void		zl_ip_set_ip4(zl_ip_t* ptr, uint32_t ip);
void		zl_ip_set_ip6(zl_ip_t* ptr, void* ip);
char* 		zl_ip_to_str(zl_ip_t* ptr, char* ret, int ret_len);
#define 	zl_ip_print(ptr)	zl_ip_to_str(ptr, alloca(40), 40)

// common.c
int			zl_init();


#endif
