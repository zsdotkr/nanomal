#ifndef __COMMON_H__
#define __COMMON_H__

// ---------- Global Macros ---------------
#define THROW_L(jmp, x, fmt, y...)  if (unlikely((x)))    \
									{   ERR(fmt " [%s/%d]",##y,  __func__, __LINE__);  goto _##jmp##_;    }
#define THROW(jmp, x)               if (unlikely((x))) {   goto _##jmp##_; }
#define CATCH(jmp, ...)     _##jmp##_:

typedef enum
{	APP_ERR = -1, 
	// IP Layer
	APP_ARP = 0, 
	APP_IP4,
	APP_IP6,
	APP_ICMP, 
	APP_IGMP, 
	// L4 Layer
	APP_UDP, 
	APP_TCP,
	APP_UNKNOWN, 
} app_t;

// ---------- prototypes ---------------

// sklist.c
char*		sklist_create(int max_nodes_approx);
void		sklist_free(char* ptr);
void		sklist_update_tm(char* ptr, int expiry_test);
void		sklist_update_tm_timeval(char* ptr, struct timeval* tm, int expiry_test);
void**		sklist_add(char* ptr, uint64_t key_g, uint64_t key_u, int expire_after);
void*		sklist_del_exact(char* ptr, uint64_t key_g, uint64_t key_u);   // delete exact node;
void*		sklist_srch_exact(char* ptr, uint64_t key_g, uint64_t key_u);  // search exact node;
int			sklist_del_grp(char* ptr, uint64_t key_g, uint64_t** key_u, void*** data_u);
int			sklist_srch_grp(char* ptr, uint64_t key_g, uint64_t** key_u, void*** data_u);
int			sklist_get_expired(char* ptr, uint64_t* key_g, uint64_t* key_u, void** data_u);
int			sklist_get_tot_nodes(char* ptr);

#endif
