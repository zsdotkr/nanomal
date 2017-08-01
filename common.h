#ifndef __COMMON_H__
#define __COMMON_H__

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
