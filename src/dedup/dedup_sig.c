/*
 * dedup_sig.c
 *
 * Functions for maintaining a signature store.
 * We use an AVL tree for quick lookup, and a circular buffer
 * for bounding the number of signatures.
 * */

#include "avltree.h"
#include "dedup_sig.h"
#include <stdlib.h>
#include <string.h> // for memcpy
#include <openssl/sha.h>
#include "dedup.h"

#define SBUF_SIZE 10000
static sig_t            sbuf[SBUF_SIZE]; // circular buffer
static unsigned int     sbuf_first = 0;
static unsigned int     sbuf_last = 0;
static AVL_Tree*        sigtree = NULL; // AVL tree to store signatures


int sigCompare( void* v, const Element* e1, const Element* e2 )
{
  int i;

  //unsigned long h1 = (unsigned long) e1;
  //unsigned long h2 = (unsigned long) e2;
  int rc = memcmp( e1, e2, SHA_DIGEST_LENGTH );
  if (rc == 0)
  {
    //dd_printf("MATCH1: ");
    //for (i = 0; i < SHA_DIGEST_LENGTH; ++i) dd_printf("%02x", ((sig_t)e1)[i]);
    //dd_printf("\n");
    //dd_printf("MATCH2: ");
    //for (i = 0; i < SHA_DIGEST_LENGTH; ++i) dd_printf("%02x", ((sig_t)e2)[i]);
    //dd_printf("\n");
  }
  return rc;
}

/*
 * Initialization.
 * */
int dd_init_sigs()
{
  sigtree = AVL_Tree_alloc2(NULL, sigCompare, malloc, free);
  if (sigtree == NULL) return -1;
  return 0;
}

/*
 * Returns true if the signature is found.
 * */
bool dd_has_sig(const sig_t sig)
{
  int i;
  //dd_printf("FND_SIG: ");
  //for (i = 0; i < SHA_DIGEST_LENGTH; ++i) dd_printf("%02x", sig[i]);
  //dd_printf("\n");

  return (AVL_find( (const Element*) sig, sigtree ) != NULL);
}

/*
 * Adds signature. We're using a circular buffer. If we need to overwrite
 * an old signature, we need to evict it from the AVL tree.
 * */
void dd_add_sig(sig_t sig)
{
  int i;
  sig_t sig_cpy = NULL;
  unsigned int b = sbuf_first;
  unsigned int e = sbuf_last < sbuf_first
    ? sbuf_last + SBUF_SIZE
    : sbuf_last;
  if ((e - b + 1) == SBUF_SIZE) {
    // Circular buffer is full, remove corresponding first element
    // of circular buffer from AVL tree.
    sig_cpy = (sig_t) AVL_delete( (const Element*) sig, sigtree );
    sbuf_first = (++sbuf_first) % SBUF_SIZE;
  }

  // Add to circular buffer
  sbuf[sbuf_last] = sig;
  sbuf_last = (++sbuf_last) % SBUF_SIZE;

  // Make a copy of sig and add to AVL tree
  //dd_printf("ADD_SIG: ");
  //for (i = 0; i < SHA_DIGEST_LENGTH; ++i) dd_printf("%02x", sig[i]);
  //dd_printf("\n");

  if (sig_cpy == NULL)
    sig_cpy = (sig_t) malloc( sizeof(unsigned char) * SHA_DIGEST_LENGTH );
  memcpy( (void*)sig_cpy, (void*)sig, sizeof(unsigned char) * SHA_DIGEST_LENGTH );
  AVL_insert( (const Element*)sig_cpy, sigtree );
}

int free_visitor(void* v, Element* e)
{
  free( e );
  return 0;
}

void dd_destroy_sigs()
{
  AVL_visit( NULL, sigtree, free_visitor );
  AVL_Tree_free( &sigtree );
}
