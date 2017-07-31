/* original reference : REDIS zskiplist (zslInsert, zslDelete, ...)
 * modified 
 * 	- remove span : span is used to calculate rank of some node  
 * 	- add key_g (group key) & key_u (unique key) instead of score
 * 	- add data : data is used for storage of user data
 * 	- add auto expiration check (add back in lvl structure)
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/times.h>

/* ---------- override below 
 */

#define ERR(x, y...)			printf(x "\n", ##y)
#define LOG(x, y...)			printf("   " x "\n", ##y)

/* ---------- internal defines 
 */

// #define LOCAL_TEST

typedef unsigned long long int 	uint64_t;

#define PTR(x)					((int)((int64_t)(x)) & 0xffff)

/* ---------- internal structures  & static variables 
 */

typedef struct snode_t
{	uint64_t		key_g;		// group key, A key_g can have multiple key_u
	uint64_t		key_u; 		// unique key
	void*			data_u;		// user data

	int64_t			expire_at;	// expire time (msec), ONLY updated afer calling sklist_add

	int				tot_lvl;	

	struct snode_lvl_t
	{	struct snode_t*	fwd;	// forward
		struct snode_t*	back;	// backward
	} lvl[]; 	// level
} snode_t;	// skiplist node

typedef struct 
{	snode_t*		head;
	snode_t*		expire_ptr;	// current pointer to check expiration 
	snode_t*		expired;	// single linked list for expired nodes
	int				lvl_max;	// maximum level for skiplist
	int				lvl_uniq;	// maximum level for key_u
	int				lvl; 		// current level (lvl > uniq_lvl)
	int				total;
	int64_t			cur_time;	// current time in msec (relative time)
} sklist_t;	// skiplist

/* ---------- internals 
 */

#ifdef LOCAL_TEST

static void dump_node(const char* title, snode_t* x, sklist_t* sl)
{	// print out skiplist node information	
	char	buf[256]; 
	int		pos, i; 

	if (x == NULL)	{	LOG("%s, NULL", title);	return;	}
	
	pos = sprintf(buf, "%s, k=%2llu/%2llu:%3u, ", title, x->key_g, x->key_u, PTR(x->data_u));

	pos += sprintf(&buf[pos], "f:");
	for(i = 0; i < x->tot_lvl; i++)
	{	if (x->lvl[i].fwd == NULL)	{	pos += sprintf(&buf[pos], " .....");	}
		else
		{	if (x->lvl[i].fwd == sl->head)
			{	pos += sprintf(&buf[pos], " HEAD ");	}
			else
			{	pos += sprintf(&buf[pos], " %2llu/%-2llu", x->lvl[i].fwd->key_g, x->lvl[i].fwd->key_u);	
			}
		}
	}
	for(; i< sl->lvl_max; i++)	{	pos += sprintf(&buf[pos], "      ");	}	

	pos += sprintf(&buf[pos], " b:");
	for(i=0; i < x->tot_lvl; i++)
	{	if (x->lvl[i].back == NULL)	{	pos += sprintf(&buf[pos], " ...");	}	
		else
		{	if (x->lvl[i].back == sl->head)	{   pos += sprintf(&buf[pos], " HEAD ");  }	
			else
			{	pos += sprintf(&buf[pos], " %2llu/%-2llu", x->lvl[i].back->key_g, x->lvl[i].back->key_u);	
			}
		}
	}
	for(; i< sl->lvl_max; i++)	{	pos += sprintf(&buf[pos], "      ");	}	

	pos += sprintf(&buf[pos], " l:%d, ex:%zd, p:%x", x->tot_lvl, 
		(x->expire_at == LLONG_MAX) ? 0 : x->expire_at % 10000, PTR(x));

	LOG("%s", buf);
}

static void dump_slist(char* ptr, int detail, const char* title, ...)
{	// dump whole skiplist 
	sklist_t*	sl  =(sklist_t*) ptr; 
	snode_t*	x; 
	int			total; 
	va_list		ap; 
	char		buf[128]; 

	va_start(ap, title);
	vsprintf(buf, title, ap);
	va_end(ap);
	LOG("----- %s : %s -----", __func__, buf);	

	LOG("lvl:%d (%d/%d), total:%d, head:%x, cur:%zd", 
		sl->lvl, sl->lvl_max, sl->lvl_uniq, 
		sl->total, PTR(sl->head), sl->cur_time % 10000);

	// dump_node("exp ", sl->expire_ptr, sl);
	dump_node("head", sl->head, sl);

	if (detail)
	{	for(x = sl->head; x && (x->lvl[0].fwd != NULL); )
		{	x = x->lvl[0].fwd; 
			dump_node(" >> ", x, sl);
		}
	}
	if (detail)
	{	for(x = sl->expired; x; x = x->lvl[0].fwd )
		{	
			dump_node(" EX ", x, sl);	
		}
	}
}

#endif // LOCAL_TEST

static int rand_lvl(int min_lvl, int max_lvl)
{	// get random level used for node's maximum level
	int		lvl = min_lvl;

	while((random() & 0xffff) < (0xffff/4))	// probability : 25%
	{	lvl += 1;	}

	return (lvl < max_lvl) ? lvl : max_lvl;
}

static void chk_expire(sklist_t* sl, int max) 
{	// check and advance expire_ptr node	
	snode_t*	x = sl->expire_ptr;
	snode_t*	expired;
	int			run, i; 

	for(run = 0; run < max; run++)
	{	
		// stop checking if last node 
		if (x == NULL)		{	x = sl->head;	break;	}

		expired = NULL;

		if (x->expire_at < sl->cur_time)
		{	// dump_node("fire", x, sl);

			// unlink x
			for(i = 0; i < x->tot_lvl; i++)
			{	if (x->lvl[i].fwd != NULL)	 // if not last node
				{	x->lvl[i].fwd->lvl[i].back = x->lvl[i].back;	
				}

				x->lvl[i].back->lvl[i].fwd = x->lvl[i].fwd;
			}

			// adjust maximum level of skiplist
			while ((sl->lvl > sl->lvl_uniq) && (sl->head->lvl[sl->lvl-1].fwd == NULL))
			{	sl->lvl -= 1;	}

			expired = x; 

			x = x->lvl[0].fwd;	

			// decr total number of skiplist
			sl->total -= 1;

			// add exired node to sl->expired
			expired->lvl[0].fwd = sl->expired; 
			sl->expired = expired;
		}
		else
		{	x = x->lvl[0].fwd;	
		}
	}

	sl->expire_ptr = x;
}

static void delete_node(sklist_t* sl, snode_t* x, snode_t**update)
{	// delete skiplist node	
	int		i; 
	
	// update level of prev/next nodes
	for(i = 0; i< sl->lvl; i++)
	{	if (update[i]->lvl[i].fwd == x)
		{	
			update[i]->lvl[i].fwd = x->lvl[i].fwd; 
			
			if (x->lvl[i].fwd && (x->lvl[i].fwd->lvl[i].back == x))
			{	x->lvl[i].fwd->lvl[i].back = update[i]; 	}	
		}
	}

	// update expire_ptr if x == expire_ptr
	if (sl->expire_ptr == x)
	{	sl->expire_ptr = x->lvl[0].fwd;	
		if (sl->expire_ptr == NULL)	{	sl->expire_ptr = sl->head;	}
	}

	// adjust maximum level of skiplist
	while ((sl->lvl > sl->lvl_uniq) && (sl->head->lvl[sl->lvl-1].fwd == NULL))
	{	sl->lvl -= 1;	}

	// decr total number of skiplist
	sl->total -= 1;
}	

static snode_t* create_node(int lvl, uint64_t key_g, uint64_t key_u)
{	// create & init skiplist node	
	snode_t*	node;
	
	if ((node = malloc(sizeof(*node) + lvl * sizeof(struct snode_lvl_t))) == NULL)
	{	ERR("%s, malloc err:%d", __func__, errno);	return NULL;	}

	node->key_g = key_g; 
	node->key_u = key_u;
	node->data_u = NULL;
	node->tot_lvl = lvl;

	return node;
}

static snode_t* srch_node(sklist_t* sl, snode_t** update, uint64_t key_g, uint64_t key_u)
{	// search exact node having key_g & key_u	
	snode_t*	x; 
	int			i;

	x = sl->head; 

	for (i = sl->lvl-1; i >= 0; i--)
	{	while	((x->lvl[i].fwd))
		{	if	((x->lvl[i].fwd->key_g < key_g)	|| 
				 ((x->lvl[i].fwd->key_g == key_g) && (x->lvl[i].fwd->key_u < key_u)))
			{	x = x->lvl[i].fwd;	}
			else
			{	break;	}
		}
		update[i] = x;
	}
	x = x->lvl[0].fwd;

	// verify key_g & key_u
	if (x && (x->key_g == key_g) && (x->key_u == key_u) && (x->expire_at >= sl->cur_time))
	{	return x;
	}
	return NULL;
}

static void update_time(char* ptr, int test_flag)
{	// order skiplist to get current time 
	// set test_flag = 0 (used ONLY for test)
	sklist_t*	sl = (sklist_t*) ptr; 

	if (ptr == NULL)	{	return;	}

	if (test_flag == 0)
	{	sl->cur_time = times(NULL) * 10;	}
	else
	{	sl->cur_time += test_flag;	}

	chk_expire(sl, 20);
}
/* ---------- libraries
 */

int sklist_get_nodes(char* ptr)
{	sklist_t*	sl = (sklist_t*) ptr; 

	if (ptr == NULL)	{	return 0;	}

	return sl->total;
}

int sklist_get_expired(char* ptr, uint64_t* key_g, uint64_t* key_u, void** data_u)
{	// return expired node 
	// return 1 (if exist) or 0 (if not exist)
	sklist_t*	sl = (sklist_t*) ptr; 	
	snode_t*	x; 

	if (sl->expired)
	{	x = sl->expired;	
		if (key_g)	{	(*key_g) = x->key_g;	}
		if (key_u)	{	(*key_u) = x->key_u;	}
		if (data_u)	{	(*data_u) = x->data_u;	}

		sl->expired = x->lvl[0].fwd; 
		free(x);
		return 1;
	}
	else
	{	return 0;	
	}
}

int sklist_srch_g(char* ptr, uint64_t key_g, uint64_t** key_u, void*** data_u)
{	// search skiplist having key_g 
	// return total number of having same key_g	
	// key_u : key_u array having same key_g (MUST be freed by caller)
	// data_u : data_u array having same key_g (MUST be freed by caller)
	sklist_t*	sl = (sklist_t*) ptr; 
	snode_t*	x; 
	snode_t*	y; 
	int			i, total, idx;

	if (ptr == NULL)	{	return 0;	}

	chk_expire(sl, 2);

	// search first node
	x = sl->head; 

	for(i = sl->lvl-1; i >= 0; i--)
	{	while 	(x->lvl[i].fwd && 
				((x->lvl[i].fwd->key_g < key_g)))
		{	x = x->lvl[i].fwd;
		}
	}

	// verify key_g
	if (x->lvl[0].fwd->key_g != key_g)
	{	if (data_u)	{	(*data_u) = NULL;	}
		if (key_u)	{	(*key_u) = NULL;	}
		return 0;
	}

	// count nodes 
	y = x->lvl[0].fwd; 
	total = 0; 

	while (y && (y->key_g == key_g))
	{	if (y->expire_at >= sl->cur_time)
		{	total++;
		}
		y = y->lvl[0].fwd;
	}

	// alloc key_u & data_u pointer
	if (key_u)	
	{	int	size = sizeof(uint64_t) * total; 	
		if (((*key_u) = (uint64_t*)malloc(size)) == NULL)
		{	ERR("%s, malloc %d Bytes err:%d", __func__, size, errno);	
			return 0;
		}
	}
	if (data_u)	
	{	int	size = sizeof(void*) * total; 	
		if (((*data_u) = (void**)malloc(size)) == NULL)
		{	ERR("%s, malloc2 %d Bytes err:%d", __func__, size, errno);
			if (key_u)	{	free (*key_u);	}
			return 0;
		}
	}

	// retrieve key_u & data_u
	x = x->lvl[0].fwd;	idx = 0;
	while (x && (x->key_g == key_g))
	{	
		if (x->expire_at >= sl->cur_time)
		{	
			if (key_u)	{	(*key_u)[idx] = x->key_u;		}
			if (data_u)	{	(*data_u)[idx] = x->data_u;	}

			idx++;
		}

		x = x->lvl[0].fwd;
	}
	return total;
}

int sklist_del_g(char* ptr, uint64_t key_g, uint64_t** key_u, void*** data_u)	
{	// delete node having same key_g	
	// return total number of having same key_g	
	// key_u : key_u array having same key_g (MUST be freed by caller)
	// data_u : data_u array having same key_g (MUST be freed by caller)
	sklist_t*	sl = (sklist_t*) ptr; 
	snode_t*	x; 
	snode_t*	y; 
	int			i, total, idx;

	if (ptr == NULL)	{	return 0;	}
	
	// assign update after vaidate of ptr
	snode_t*	update[sl->lvl_max]; 

	x = sl->head; 

	for(i = sl->lvl-1; i >= 0; i--)
	{	while 	(x->lvl[i].fwd && ((x->lvl[i].fwd->key_g < key_g)))
		{	x = x->lvl[i].fwd;
		}
		update[i] = x;	
	}

	// verify key_g
	if (x->lvl[0].fwd->key_g != key_g)
	{	if (data_u)	{	(*data_u) = NULL;	}
		if (key_u)	{	(*key_u) = NULL;	}
		return 0;
	}

	// count nodes 
	y = x->lvl[0].fwd; 
	total = 0; 
	while (y && (y->key_g == key_g))
	{	if (y->expire_at >= sl->cur_time)
		{	total++;	}

		y = y->lvl[0].fwd;
	}

	if (key_u)	
	{	int	size = sizeof(int64_t) * total;	
		if (((*key_u) = (uint64_t*) malloc(size)) == NULL)
		{	ERR("%s, malloc %d Bytes err:%d", __func__, size, errno);	
			return 0;
		}	
	}
	if (data_u)	
	{	int	size = sizeof(void*) * total; 	
		if (((*data_u) = (void**)malloc(size)) == NULL)
		{	ERR("%s, malloc2 %d Bytes err:%d", __func__, size, errno);
			if (key_u)	{	free (key_u);	}
			return 0;
		}
	}

	x = x->lvl[0].fwd; 
	idx = 0; 
	while (x && (x->key_g == key_g))
	{	if (x->expire_at >= sl->cur_time)
		{	if (key_u)	{	(*key_u)[idx] = x->key_u;	}
			if (data_u)	{	(*data_u)[idx] = x->data_u;	}
			idx++;
		}
		// TODO unlink 

		y = x->lvl[0].fwd; 
		delete_node(sl, x, update);
		x = y;
	}	
	return total;
}

void* sklist_srch_e(char* ptr, uint64_t key_g, uint64_t key_u)	// search exact node
{	// search node having key_g & key_u	
	// return user_data
	// return NULL if error
	sklist_t*	sl = (sklist_t*) ptr; 
	snode_t*	x; 

	if (ptr == NULL)	{	return NULL;	}

	chk_expire(sl, 2);

	// assign update after vaidate of ptr
	snode_t*	update[sl->lvl_max]; 

	if ((x = srch_node(sl, update, key_g, key_u)) != NULL)
	{	return x->data_u; 	
	}
	return NULL;	
}

void* sklist_del_e(char* ptr, uint64_t key_g, uint64_t key_u)	// delete exact node
{	// delete node having key_g & key_u	
	// return user_data
	// return NULL if error
	sklist_t*	sl = (sklist_t*) ptr; 
	snode_t*	x; 

	if (ptr == NULL)	{	return NULL;	}

	// assign update after vaidate of ptr
	snode_t*	update[sl->lvl_max]; 

	if ((x = srch_node(sl, update, key_g, key_u)) != NULL)
	{	void*	data_u;	

		delete_node(sl, x, update);
		data_u = x->data_u;
		free (x);
		return data_u; 	
	}
	LOG("%s, k=%llx:%llx, not found", __func__, key_g, key_u);
	return NULL;	
}

void** sklist_add(char* ptr, uint64_t key_g, uint64_t key_u, int expire_after)
{	// add node to skitlist	
	// expire_after in seconds 
	// return pointer for data_u with NULL ((*return) == NULL) if newly added 
	// return pointer for data_u with some data ((*return) != NULL) if already exist
	// return NULL if error

	sklist_t*	sl = (sklist_t*)ptr; 
	snode_t*	x; 
	int			i, lvl;

	if (ptr == NULL)	{	return NULL;	}

	chk_expire(sl, 2);

	// assign update after vaidate of ptr
	snode_t*	update[sl->lvl_max]; 

	x = sl->head; 	

	for (i = sl->lvl-1; i >= 0; i--)
	{	while	(x->lvl[i].fwd)
		{	if	((x->lvl[i].fwd->key_g < key_g) || 
				 ((x->lvl[i].fwd->key_g == key_g) && (x->lvl[i].fwd->key_u < key_u)))
			{	x = x->lvl[i].fwd;	}
			else
			{	break;	}
		}
		update[i] = x;
	}

	// At this point, x = update[0]; 

	// return &data_u if already existed node
	if (update[0]->lvl[0].fwd)
	{	snode_t*	t = update[0]->lvl[0].fwd; 
		if ((t->key_g == key_g) && (t->key_u == key_u))
		{		
			if (expire_after > 0)		// reset expiration 
			{	t->expire_at = sl->cur_time + (expire_after * 1000);		}
			return &t->data_u;	
		}
	}	

#if 0 
	if (update[0]->lvl[0].fwd && (update[0]->lvl[0].fwd->key_g == key_g))
	{	lvl = rand_lvl(1, sl->lvl_uniq);	}
	else
	{	lvl = rand_lvl(sl->lvl_uniq+1, sl->lvl_max);	}
#else
	lvl = rand_lvl(1, sl->lvl_max);
#endif

	if (lvl > sl->lvl)
	{	for(i=sl->lvl; i < lvl; i++)
		{	
			update[i] = sl->head; 
		}
		sl->lvl = lvl; 
	}

	x = create_node(lvl, key_g, key_u);

	for(i = 0; i < lvl; i++)
	{	x->lvl[i].fwd = update[i]->lvl[i].fwd; 
		if (x->lvl[i].fwd)	{	x->lvl[i].fwd->lvl[i].back = x;	}
		x->lvl[i].back = update[i]; 
		update[i]->lvl[i].fwd = x; 
	}

	if (x->lvl[0].fwd)	{	x->lvl[0].fwd->lvl[0].back = x; 	}

	// set expiration 
	if (expire_after > 0)
	{	x->expire_at = sl->cur_time + (expire_after * 1000);	}
	else
	{	x->expire_at = LLONG_MAX; }

	sl->total ++;

	return &x->data_u;
}

void sklist_free(char* ptr)
{	sklist_t*	sl = (sklist_t*) ptr; 
	snode_t*	x;
	snode_t*	next;

	if (ptr == NULL)	{	return;	}

	x = sl->head->lvl[0].fwd; 
	
	// free nodes
	while(x)
	{	next = x->lvl[0].fwd; 
		free(x);
		x = next;	
	}

	// free head & myself
	free(sl->head);
	free(sl);
}


void sklist_update_time(char* ptr)
{	update_time(ptr, 0);	}

char* sklist_create(int max_nodes_approx)
{	// create skiplist	
	// max_nodes_approx : expected maximum nodes (to adjust max_lvl)
	sklist_t*	sl; 
	int			i;
	int			max_lvl = 4;
	int			uniq_lvl = 2; 

#if 1
	if 		(max_nodes_approx == 0)			{	uniq_lvl = 3;	max_lvl = 12;	}
	else if (max_nodes_approx <= 1000)		{	uniq_lvl = 2;	max_lvl = 4;	}
	else if (max_nodes_approx <= 10000)		{	uniq_lvl = 1;	max_lvl = 4;	}
	else if (max_nodes_approx <= 100000)	{	uniq_lvl = 2;	max_lvl = 6;	}
	else if (max_nodes_approx <= 1000000)	{	uniq_lvl = 2;	max_lvl = 12;	}
	else									{	uniq_lvl = 3;	max_lvl = 12;	}
#endif

	if ((sl = malloc(sizeof(*sl))) == NULL)	
	{	ERR("%s, malloc err:%d", __func__, errno);	return NULL;	}

	sl->lvl_max = max_lvl;
	sl->lvl_uniq = uniq_lvl; 
	sl->lvl = uniq_lvl; 
	sl->total = 0; 

	sl->head = create_node(max_lvl, 0, 0);
	sl->head->expire_at = LLONG_MAX;

	sl->expire_ptr = sl->head;
	sl->expired = NULL;

	for(i=0; i< max_lvl; i++)
	{	sl->head->lvl[i].fwd = NULL; 
		sl->head->lvl[i].back = NULL;
	}

	update_time((char*)sl, 0);

	return (char*) sl;
}

#ifdef LOCAL_TEST
/* ---------- test main
 */

int64_t get_msec()
{	int64_t	ret;
	ret = times(NULL);
	ret *= 10;
	return ret;
}

void sklist_add_my(char* sl, uint64_t key_g, uint64_t key_u, int data, int expire_at)
{	void** ret; 

	ret = sklist_add(sl, key_g, key_u, expire_at); 

	if (ret == NULL)
	{	ERR("%s, fail, k=%llu/%llu/%d", __func__, key_g, key_u, data);	}
	else
	{	if ((*ret) == NULL)		// newly added
		{	(*ret) = (void*)(int64_t)data;	}
		else					// overwrite old value
		{	(*ret) = (void*)(int64_t)data; }
	}
}

void prt_key_grp(const char* title, int k, int total,  uint64_t* kup, void** dup)
{	int		d, ku, i, pos; 
	char	buf[128];

	pos = sprintf(buf, "%s, key group,g=%d,", title, k);
	for (i = 0; i < total; i++)
	{	ku = kup[i];
		d = (int)(int64_t)dup[i];	
		pos += sprintf(&buf[pos], " %d:%d", ku, d);
	}
	LOG("%s", buf);
}

void rand_add_del(char* sl, int max, int detail)
{	int		ptn_add[] = {1, 2, 9, 8, 0, 3, 5, 7, 6, 4};
	int		ptn_del[] = {2, 1, 6, 4, 0, 9, 7, 8, 3, 5};
	int		ptn_sub[] = {3, 2, 1, 4, 9, 8, 7, 5, 6, 11};
	int		key, off, k2, cnt, k3, total; 
	int64_t	st, en; 

	for(total = 0, key = 0; key < 10; key++)
	{	sklist_add_my(sl, ptn_add[key], ptn_add[key], key, 0);	total++;

		for(k3 = 0; k3 < key; k3++)
		{	sklist_add_my(sl, key, k3, 0, 0);	total++;	}

		for(k3 = key+1; k3 < key+2; k3++)
		{	sklist_add_my(sl, key, k3, 0, 0);	total++;	}
	}
	dump_slist(sl, detail, "add %d, order: random", total);

	for(total = 0, key = 9; key >= 0; key--)
	{	if (sklist_del_e(sl, ptn_del[key], ptn_del[key]) != NULL)	{	total++;	}

		for(k3 = key+1; k3 < key+2; k3++)
		{	if (sklist_del_e(sl, key, k3) != NULL)		{	total++;	}	}
		for(k3 = 0; k3 < key; k3++)
		{	if (sklist_del_e(sl, key, k3) != NULL)		{	total++;	}	}
	}
	dump_slist(sl, detail, "del %d, order: random", total);
}

void del(char* sl, int max, int detail)
{	int		key, i; 
	int64_t	st, en; 

	st = get_msec();
	for(key = 0; key < max; key++)
	{	sklist_add_my(sl, key, key, key, 0);	}
	en = get_msec();

	dump_slist(sl, detail, "%zd [ms], after ADD, order:0 --> %d", en-st, max-1);

	st = get_msec(); 
	for(key = 0; key < max; key++)
	{	sklist_del_e(sl, key, key);	}
	en = get_msec(); 

	dump_slist(sl, detail, "%zd [ms], after remove ALL, order:0 --> %d", en-st, max-1);

	st = get_msec();
	for(key = max-1; key >= 0; key--)
	{	sklist_add_my(sl, key, key, key, 0);	}
	en = get_msec();

	dump_slist(sl, detail, "%zd [ms], after ADD, order:%d --> 0", en-st, max-1);

	st = get_msec(); 
	for(key = (max-1); key >= 0; key--)
	{	sklist_del_e(sl, key, key);	}
	en = get_msec(); 

	dump_slist(sl, detail, "%zd [ms], after remove ALL, order:%d --> 0", en-st, max-1);
}

void add(char* sl, int max, int detail)
{	int		key, i; 	
	int64_t	st, en;

	dump_slist(sl, detail, "before ADD %d entry", max);

	st = get_msec();
	for(key = 0; key < max; key++)
	{	sklist_add_my(sl, key, key, key, 0);	}
	en = get_msec();

	dump_slist(sl, detail, "%zd [ms], after ADD, order:0 --> %d", en-st, max-1);

	st = get_msec();
	for(i = 0, key = max-1; key >= 0; key--, i++)
	{	sklist_add_my(sl, key, key, i, 0);	}
	en = get_msec();

	dump_slist(sl, detail, "%zd [ms], after modify data, 0 ~ %d ==> %d ~ 0", en-st, max-1, max-1);
}

void test(char* ptr, int max, int detail)
{	int			k, ku, cnt; 
	void*		ret;
	uint64_t*	key_u; 
	void**		data_u;
	char*		sl; 
	int			min_d = 2, max_d = 4;
	int			min_u = 1, max_u = 6; 
	int			err;

	sl = sklist_create(max);

	for(k = 1; k < max; k++)
	{	sklist_add_my(sl, k, k, k, 0);	}
	dump_slist(sl, detail, "after ADD"); 
	
	for(k = 1; k < max; k++)
	{	sklist_add_my(sl, k, k, k + 100, 0);	}
	dump_slist(sl, detail, "after UPDATE"); 

	// add key_u
	for(k = 1; k < max; k++)
	{	for (ku = 0; ku < k; ku++)
		{	sklist_add_my(sl, k, ku, ku, 0);	}
		for(ku = k+1; ku < k+3; ku++)
		{	sklist_add_my(sl, k, ku, ku, 0);	}
	}
	dump_slist(sl, detail, "add key_u"); 

	// test srch_e
	if ((ret = sklist_srch_e(sl, max, max)) != NULL)
	{	ERR("srch_e error, line:%d", __LINE__);	}
	else
	{	LOG("k= %d/%d not found ==> OK", max, max);	}

	for(err = 0, k = 1; k < max; k++)
	{	if ((ret = sklist_srch_e(sl, k, k)) == NULL)
		{	ERR("srch_e err, k:%d, line:%d", k, __LINE__);	err++;	}
	}
	if (err == 0)	{	LOG("srch 1 ~ %d ==> OK", max-1);	}

	// test srch_g
	for (err = 0, k = 1; k < max; k++)
	{	
		cnt = sklist_srch_g(sl, k, &key_u, &data_u);
		if (cnt != (k + 3))
		{	ERR("srch_g err, k:%d, cnt:%d, line:%d", k, cnt, __LINE__); err++;	}
		prt_key_grp("searched", k, cnt, key_u, data_u);
		free(key_u);
		free(data_u);
	}
	if (err == 0)	{	LOG("srch_g ==> OK");	}
	
	// test del_e
	for(err = 0, k = 1; k < max; k++)
	{	if (sklist_del_e(sl, k, k) == NULL)
		{	ERR("del_e err, k:%d, line:%d", k, __LINE__);	err++;	}
	}
	if (err == 0)	{	LOG("del_e ==> OK");	}
	dump_slist(sl, detail, "after del_e"); 

	// test del_g
	for(err = 0, k = (max-1); k >= 1; k--)
	{	cnt = sklist_del_g(sl, k, &key_u, &data_u); 
		if (cnt != (k+2))
		{	ERR("del_g err, k:%d, cnt:%d, l:%d", k, cnt, __LINE__); err++;	}
		prt_key_grp("deleted", k, cnt, key_u, data_u);
		free(key_u);
		free(data_u);
	}
	if (err == 0)	{	LOG("del_g ==> OK");	}
	dump_slist(sl, detail, "after del_g"); 

}

void expire(char* sl, int max, int detail)
{	int		k, cnt;

	update_time(sl, 1000);

	for(k = (max-1); k >= 1; k--)	{	sklist_add_my(sl, k, k, k, 1);	}
	dump_slist(sl, detail, "after ADD");

	for(k = 1; k < max; k++)		{	update_time(sl, 1000);	}
	dump_slist(sl, detail, "after update time");

	for(k = 1, cnt = 1; k < max; k++)
	{	cnt += sklist_get_expired(sl, NULL, NULL, NULL); }
	if (cnt == max)	{	LOG("Expire ALL ==> OK");	}
	else			{	LOG("Expire %d ==> ERR", cnt);	}

	for(k = 1; k < max; k ++)
	{	sklist_add_my(sl, k, k, k, 0);	}
	dump_slist(sl, detail, "after ADD");

	for(k = 1; k < max; k++) 
	{	for(cnt = 1; cnt < (k+2); cnt++)
		{	if (cnt != k)	{	sklist_add_my(sl, k, cnt, k, 1);		}
		}
	}
	dump_slist(sl, detail, "after ADD");

	for(k = 1; k < max; k++)		{	update_time(sl, 1000);	}
	dump_slist(sl, detail, "after update time");
}

int main(int argc, char* argv[])
{	int			max; 
	char*		sl; 
	int64_t		st, en;
	int			detail; 
	int			method;

	method = -1;
	max = 10; 
	detail = 1;

	if (argc >= 4)	{	detail = atoi(argv[3]);	}
	if (argc >= 3)	{	max = atoi(argv[2]);	}

	if (max >= 1000)	{	detail = 0;	}

	sl = sklist_create(max);

	if (argc >= 2)
	{	method = atoi(argv[1]);	
		st = get_msec();	
		switch (method)
		{	case 1:		add(sl, max, detail);	break;
			case 2:		del(sl, max, detail);	break;
			case 3:		rand_add_del(sl, max, detail);	break;
			case 4:		expire(sl, max, detail);	break;
			case -1:	test(sl, max, detail);	break;
		}
		en = get_msec();
		printf("\nElapsed Time : %zd [msec]\n", en - st);
	}
	else
	{	printf("nothing to do\n");	}

	return 0; 
}

#endif // LOCAL_TEST
