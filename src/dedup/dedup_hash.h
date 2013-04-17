#ifndef __DEDUP_HASH_HEADER__
#define __DEDUP_HASH_HEADER__

#include <stdlib.h>
#include <openssl/sha.h>

unsigned long dd_hash(const char *str);
unsigned long dd_sieve_hash(
    const char *ins,
    //int len,
    const int type );
void dd_sieve_sha1( const char* ins, const int type, SHA_CTX* sha_ctx );

#endif
