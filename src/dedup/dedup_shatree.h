#ifndef __DEDUP_SHATREE_HEADER__
#define __DEDUP_SHATREE_HEADER__

#ifdef __KERNEL__
#include <linux/slab.h>
#else
#include <stdbool.h>
#endif

void ddst_init(void);
void ddst_destroy(void);
bool ddst_has_sha1( unsigned char* sha1 );
#ifdef __KERNEL__
void ddst_insert_sha1( unsigned char* sha1, gfp_t gfp_mask );
#else
void ddst_insert_sha1( unsigned char* sha1 );
void ddst_print();
#endif

#endif
