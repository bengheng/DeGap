#ifdef __KERNEL__
#include <linux/string.h> // for memcpy, memcmp, memset
#include <linux/slab.h> // for kmalloc
#else
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h>
#endif

#ifdef __KERNEL__
#define SHA_DIGEST_LENGTH  32
#define NUM_SUCCESSOR         256           // 2^8
#define CBUF_SIZE             64
#else
#define NUM_SUCCESSOR (UCHAR_MAX + 1)
#define CBUF_SIZE     6
#endif
#define MAX_LEVEL     3             // Max level before leaves
#define EVICT_COUNT   (CBUF_SIZE/2) // Evict half of cbuf
#define SUFFIX_BYTES  ((SHA_DIGEST_LENGTH - MAX_LEVEL) * sizeof(unsigned char))

// Clock Algorithm:
// r is set whenever cell is referenced.
// Clock hand sweeps over cells looking for one with r = 0.

#define IS_REFD(f)  ( f & 1 ) // for clock algorithm
#define IS_USED(f)  ( f & 2 ) // for determining if cell is in use
#define SET_REFD(f)  ( f |= 1 )
#define SET_USED(f)  ( f |= 2 )
#define CLEAR_REFD(f)  ( f &= ~1 )
#define CLEAR_USED(f)  ( f &= ~2 )

typedef struct _Cell
{
  unsigned char   suffix[SUFFIX_BYTES];
  int             flags;
  struct _Cell*   next; // points to next used or unused cell
  struct _Cell*   prev; // points to previous used or unused cell
} Cell;


/*
 * There is a lot of redundancy in the way we are managing used and unused
 * cells. The reason for these redundancies is to allow us to be able to
 * access different cells quickly. For example, the flags allow us to
 * immediately tell if the cell is used or not. The used and unused chains
 * allow us to respectively quickly get a used or unused cell.
 * */
typedef struct _Leaf
{
  unsigned int    idx;               // circular buffer index
  Cell            cbuf[ CBUF_SIZE ]; // circular buffer

  /* Head always points to the first cell. Tail always points to the last
   * cell.
   *
   * If both head and tail are pointing to the same cell, then that is the
   * last cell in the chain.
   *
   * If both head and tail are pointing to NULL, then the chain is empty.
   *
   * In other words, it is not possible for head to be non-NULL while tail
   * is NULL, and vice-versa. Both are either NULL or non-NULL simultaneously.
   * */
  Cell*           used_head;
  Cell*           used_tail;
  Cell*           clock_hand;

  Cell*           unused_head;
  Cell*           unused_tail;
} Leaf;

typedef struct _Node
{
  union _next {
    struct _Node* nodes[NUM_SUCCESSOR];
    struct _Leaf* leaves[NUM_SUCCESSOR];
  } next;
} Node;


static Node root;

//=============================================================================

void ddst_init(void)
{
  memset( &root.next.nodes[0], 0x0,
      sizeof(struct _Node*) * NUM_SUCCESSOR );
#ifdef __KERNEL__
  printk( KERN_INFO "NBH Initialized ddst" );
#endif
}

//=============================================================================


/*
 * Helper function for recursively destroying nodes.
 * */
static void ddst_destroy_helper( Node* node, int level )
{
  int i;
#ifdef __KERNEL__
  if (node == NULL) return;
#else
  assert( node != NULL );
#endif

  if (level == MAX_LEVEL)
  {
    for (i = 0; i < NUM_SUCCESSOR; ++i)
    {
      Leaf* l = node->next.leaves[i];
      if (l != NULL)
#ifdef __KERNEL__
        kfree( l );
#else
        free( l );
#endif
    }
  }
  else
  {
    for (i = 0; i < NUM_SUCCESSOR; ++i)
    {
      Node* child = node->next.nodes[i];
      if (child == NULL) continue;

      ddst_destroy_helper( child, level+1 );
#ifdef __KERNEL__
      kfree( child );
#else
      free( child );
#endif
    }
  }
}

/*
 * Frees all memory.
 * */
void ddst_destroy(void)
{
  ddst_destroy_helper( &root, 0 );
}

//=============================================================================

/*
 * Returns true if leaf already has sha1.
 * */
static bool ddst_has_sha1_in_leaf(
    Leaf *l,
    unsigned char* sha1 )
{
  int i;

  if (l == NULL || sha1 == NULL)
    return false;

  for (i = 0; i < CBUF_SIZE; ++i)
  {
    if ( !IS_USED(l->cbuf[i].flags) ) continue;
    if ( memcmp( l->cbuf[i].suffix, &sha1[MAX_LEVEL], SUFFIX_BYTES ) == 0 )
    {
      SET_REFD( l->cbuf[i].flags );
      return true;
    }
  }
  //printf("Not found in leave %x\n", l);
  return false;
}

//-----------------------------------------------------------------------------

#ifndef __KERNEL__
static void ddst_print_chain( Cell* head, Cell* tail, Cell* clock_hand )
{
  int i;
  Cell* c = head;
  while (c != NULL )
  {
    printf( "%x %d %d%s %02x",
        c, IS_USED(c->flags), IS_REFD(c->flags),
        c == clock_hand ? "*" : " ",
       c->suffix[SUFFIX_BYTES-1] );
    //for (i = 0; i < SUFFIX_BYTES; ++i)
    //{
    //  printf("%02x ", c->suffix[i]);
    //}
    printf("\n");
    c = c->next;
  }
  printf("............\n");
}
#endif

/*
 * Removes cell from chain defined by head and tail.
 * */
static void ddst_remove_cell( Cell** head, Cell** tail, Cell* c )
{
  if (c == NULL) return;
  if (c->prev != NULL) c->prev->next = c->next;
  if (c->next != NULL) c->next->prev = c->prev;
  if (c == *head) *head = c->next;
  if (c == *tail) *tail = c->prev;
  c->prev = NULL;
  c->next = NULL;
}

/*
 * Removes head cell in the chain defined by head and tail.
 * */
static Cell* ddst_remove_head( Cell** head, Cell** tail )
{
  Cell* c = *head;
  ddst_remove_cell( head, tail, c );
  return c;
}

/*
 * Appends cell to tail of chain defined by head and tail.
 * */
static void ddst_append_tail( Cell** head, Cell** tail, Cell* c )
{
  if (c == NULL) return;

  if (*head == NULL) *head = c; /* empty chain */
  if (*tail != NULL) {
    c->prev = *tail;
    (*tail)->next = c;
  }
  *tail = c;
  c->next = NULL;
} 

/*
 * Returns an unused Cell. The returned Cell is moved from the unused chain
 * to the used chain.
 * */
static Cell* ddst_get_unused_cell(Leaf* l)
{
  Cell* c = ddst_remove_head( &l->unused_head, &l->unused_tail );
  if ( c != NULL )
  {
    ddst_append_tail( &l->used_head, &l->used_tail, c );
    SET_USED( c->flags );

    // Set clock_hand if this is the first node.
    if (l->used_head == l->used_tail)
      l->clock_hand = l->used_head;
  }
  return c;
}

/*
 * Moves Cell from used chain to unused chain.
 * */
static void ddst_put_unused_cell(Leaf* l, Cell* c)
{
#ifdef __KERNEL__
  if (l == NULL || c == NULL)
    return;
#else
  assert( l != NULL );
  assert( c != NULL );
#endif

  // Move clock_hand out of the way if it is pointing to the
  // cell that we're going to remove from the used chain.
  if (c == l->clock_hand)
    l->clock_hand = c->next == NULL
      ? l->used_head
      : c->next;

  ddst_remove_cell( &l->used_head, &l->used_tail, c );
  ddst_append_tail( &l->unused_head, &l->unused_tail, c );
  CLEAR_USED( c->flags );
}

/*
 * Gets a cell for eviction from the used chain, using clock algorithm.
 *
 * Note that this function does not actually remove the cell from
 * the used chain to the unused chain. It is up to the caller what it
 * wants to do with the cell.
 * */
static Cell* ddst_get_evict_cell( Leaf* l )
{
  if (l->clock_hand == NULL)
    return NULL;

  while (true) {
#ifndef __KERNEL__
    ddst_print_chain( l->used_head, l->used_tail, l->clock_hand );
#endif

    if ( !IS_REFD( l->clock_hand->flags ) ) {
      Cell* c = l->clock_hand;
#ifdef __KERNEL__
      printk( KERN_INFO "NBH Evicting\n" );
#else
      printf("Evicting %x %02x\n----------\n", c, c->suffix[SUFFIX_BYTES-1]);
#endif
      l->clock_hand = l->clock_hand->next;
      if (l->clock_hand == NULL)
        l->clock_hand = l->used_head;
      return c;
    }
    else CLEAR_REFD( l->clock_hand->flags );

    l->clock_hand = l->clock_hand->next;
    if ( l->clock_hand == NULL )
      l->clock_hand = l->used_head;
  }

  // shouldn't reach me!
#ifndef __KERNEL__
  assert(false);
#endif
  return NULL;
}

/*
 * Insert leaf.
 * */
static void ddst_insert_leaf( Leaf* l, unsigned char* sha1 )
{
  int i = 0;
  Cell* c;

#ifdef __KERNEL__
  if (l == NULL || sha1 == NULL) return;
#else
  assert( l != NULL );
  assert( sha1 != NULL );
#endif

  if (ddst_has_sha1_in_leaf(l, sha1) == true)
    return;

  // If there is free buffer, use it.
  c = ddst_get_unused_cell( l );
  if (c != NULL)
  {
    memcpy( c->suffix, &sha1[MAX_LEVEL], SUFFIX_BYTES );
    SET_REFD( c->flags );
    return;
  }

  // No free buffer, need eviction. Note that we don't bother moving the
  // evicted cell from the used chain to the unused chain, and then
  // moving it back again.
  c = ddst_get_evict_cell( l );
#ifdef __KERNEL__
  if (c == NULL) return;
#else
  assert( c != NULL );
#endif
  memcpy( c->suffix, &sha1[MAX_LEVEL], SUFFIX_BYTES );
  SET_REFD( c->flags );

  // Evict even more
  for (i = 0; i < EVICT_COUNT; ++i)
  {
    Cell* e = ddst_get_evict_cell( l );
    ddst_put_unused_cell( l, e );
  }
}

/*
 * Insert helper.
 * */
static void ddst_insert_helper(
    Node* node,
    unsigned char* sha1,
    int level
#ifdef __KERNEL__
    , gfp_t gfp_mask
#endif
    )
{
  int i;
  unsigned char value = sha1[level];

#ifdef __KERNEL__
  if (node == NULL) return;
#else
  assert( node != NULL );
#endif

  if (level == MAX_LEVEL)
  {
    // Get child leaf. Allocate if doesn't exist.
    Leaf* leaf = node->next.leaves[value];
    if (leaf == NULL)
    {
#ifdef __KERNEL__
      leaf = (Leaf*) kmalloc( sizeof(Leaf), gfp_mask );
#else
      leaf = (Leaf*) malloc( sizeof(Leaf) );
#endif

      // Chain all unused cells. We could have used
      // ddst_put_unused_cell(), but since we know all
      // cells are unused, we can speed things up by
      // using our own for-loop.

      leaf->cbuf[0].prev = NULL;
      leaf->cbuf[0].next = &leaf->cbuf[1];
      CLEAR_USED(leaf->cbuf[0].flags);
      for (i = 1; i < (CBUF_SIZE - 1); ++i)
      {
        leaf->cbuf[i].prev = &leaf->cbuf[i-1];
        leaf->cbuf[i].next = &leaf->cbuf[i+1];
        CLEAR_USED(leaf->cbuf[i].flags);
      }
      leaf->cbuf[CBUF_SIZE - 1].prev = &leaf->cbuf[CBUF_SIZE - 2];
      leaf->cbuf[CBUF_SIZE - 1].next = NULL;
      CLEAR_USED(leaf->cbuf[CBUF_SIZE - 1].flags);

      leaf->unused_head = &leaf->cbuf[0];
      leaf->unused_tail = &leaf->cbuf[CBUF_SIZE - 1];
      leaf->used_head = NULL;
      leaf->used_tail = NULL;
      leaf->clock_hand = NULL;

      leaf->idx = 0;
      node->next.leaves[value] = leaf;
    }

    ddst_insert_leaf( leaf, sha1 );
  }
  else
  {
    // Get child node. Allocate if doesn't exist.
    Node* child = node->next.nodes[value];
    if (child == NULL)
    {
#ifdef __KERNEL__
      child = (Node*) kmalloc( sizeof(Node), gfp_mask );
#else
      child = (Node*) malloc( sizeof(Node) );
#endif
      memset( child, 0x0, sizeof(Node) );
      //printf("%d: Creating child %x for value %02x\n", level, child, value);
      node->next.nodes[value] = child;
    }

#ifdef __KERNEL__
    ddst_insert_helper( child, sha1, ++level, gfp_mask );
#else
    ddst_insert_helper( child, sha1, ++level);
#endif
  }
}

/*
 * Inserts SHA1.
 * */
#ifdef __KERNEL__
void ddst_insert_sha1( unsigned char* sha1, gfp_t gfp_mask )
#else
void ddst_insert_sha1( unsigned char* sha1 )
#endif
{
#ifdef __KERNEL__
  ddst_insert_helper( &root, sha1, 0, gfp_mask );
#else
  ddst_insert_helper( &root, sha1, 0 );
#endif
}

//=============================================================================

static bool ddst_has_sha1_helper(
    Node* node,
    unsigned char* sha1,
    int level )
{
  unsigned char value;

  if (node == NULL || sha1 == NULL) return false;

  value = sha1[level];

  if (level == MAX_LEVEL)
  {
    //printf("Finding in leave %x value %02x\n",
    //    node->next.leaves[value],
    //    value);
    return ddst_has_sha1_in_leaf( node->next.leaves[value], sha1 );
  }
  else
  {
    //printf("Finding in %x value %02x\n",
    //    node->next.nodes[value],
    //    value);
    return ddst_has_sha1_helper( node->next.nodes[value], sha1, ++level );
  }
}

bool ddst_has_sha1( unsigned char* sha1 )
{
  return ddst_has_sha1_helper( &root, sha1, 0 );
}

//=============================================================================
#ifndef __KERNEL__
/*
 * Helper function to print leaf.
 * */
void ddst_print_leaf_helper( Leaf* l )
{
  int i, j;
  int n = (SHA_DIGEST_LENGTH - MAX_LEVEL);

  for (i = 0; i < CBUF_SIZE; ++i)
  {
    if ( IS_USED( l->cbuf[i].flags ) )
    {
      printf("L%x ", l);

      for (j = 0; j < MAX_LEVEL; ++j) printf( "  " );
      for (j = 0; j < n; ++j)     printf("%02x", l->cbuf[i].suffix[j]);
      printf("\n");
    }
  }
}

/*
 * Helper function to print node.
 * */
void ddst_print_helper(Node *node, int level)
{
  int i, j;
  assert( node != NULL );
  if (level == MAX_LEVEL)
  {
    for (i = 0; i < NUM_SUCCESSOR; ++i)
    {
      Leaf* l = node->next.leaves[i];
      if (l != NULL) 
      {
        ddst_print_leaf_helper( l );
      }
    }
  }
  else
  {
    for (i = 0; i < NUM_SUCCESSOR; ++i)
    {
      Node* child = node->next.nodes[i];
      if (child != NULL)
      {
        printf("N%x ", child);
        for (j = 0; j < level; ++j) printf("  ");
        printf("%02x\n", i);
        ddst_print_helper( child, level+1 );
      }
    }
  }
}

/*
 * Prints SHA1 tree.
 * */
void ddst_print()
{
  ddst_print_helper( &root, 0 );
}
#endif
//=============================================================================
