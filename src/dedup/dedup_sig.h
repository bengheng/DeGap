#ifndef __DEDUP_SIG_HEADER__
#define __DEDUP_SIG_HEADER__

#include <stdbool.h>

//typedef unsigned long sig_t;
typedef unsigned char* sig_t;

int  dd_init_sigs();
void dd_destroy_sigs();
bool dd_has_sig(const sig_t sig);
void dd_add_sig(sig_t sig);

#endif
