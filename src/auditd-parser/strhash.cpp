#include <string.h>
#include <locale>
#include <list>
#include <unordered_map>
#include "strhash.h"

using namespace std;

/*!
 * Returns a hash of the string s with length len (such as those obtained from strlen).
 * */
hash_t calcStrHash(const char* s, const size_t len)
{
  locale loc; // the "C" locale
  const collate<char>& coll = use_facet<collate<char> >(loc);
  return coll.hash(s, s + len);
}


/*!
 * Generates a string hash, and enters it into strlut if it doesn't already exits.
 * */
hash_t getStrHash(strlut_t &strlut, const char *str)
{
  size_t len = strlen(str);
  hash_t hash = calcStrHash(str, len);
  if (strlut.find(hash) == strlut.end())
  { // not found. create new string
    char *s = new char[len+1];
    strncpy(s, str, len+1);
    strlut[hash] = s;
  }
  return hash;
}

/*!
 * Generates a buffer hash (non-null terminated), and enters it into
 * strlut if it doesn't already exits.
 * */
hash_t getBufHash(strlut_t &strlut, const char *buf, const size_t nb)
{
  hash_t hash = calcStrHash(buf, nb);
  if (strlut.find(hash) == strlut.end())
  { // not found. create new string
    char *s = new char[nb+1];
    strncpy(s, buf, nb);
    s[nb] = '\0';
    strlut[hash] = s;
  }
  return hash;
}

/*!
 * Tokenizes an input string based on the delimiter, and fills the list
 * with the hash of each token.
 *
 * NOTE: As the function is implemented using strtok_r, str can be modified.
 * Caller should save a copy if needed.
 * */
void splitStrToHashList(
    strlut_t &strlut,
    char *str,
    const char *delim,
    list< hash_t > &hashlist)
{
  char *saveptr;
  char *token;

  // tokenize str
  token = strtok_r(str, delim, &saveptr);
  while (token != NULL)
  {
    hash_t hash = getStrHash(strlut, token);
    hashlist.push_back(hash);
    token = strtok_r(NULL, delim, &saveptr);
  }
}

/*!
 * Tokenizes an input path based on the delimiter, dropping "." names,
 * and fills the list with the hash of each token.
 *
 * NOTE: As the function is implemented using strtok_r, str can be modified.
 * Caller should save a copy if needed.
 * */
void splitPathToHashList(
    strlut_t &strlut,
    char *str,
    const char *delim,
    list< hash_t > &hashlist)
{
  char *saveptr;
  char *token;

  // tokenize str
  token = strtok_r(str, delim, &saveptr);
  while (token != NULL)
  {
    if (strcmp(token, ".") == 0)
    { // skip "."
      token = strtok_r(NULL, delim, &saveptr);
      continue;
    }
    hash_t hash = getStrHash(strlut, token);
    hashlist.push_back(hash);
    token = strtok_r(NULL, delim, &saveptr);
  }
}

void printStrHash( const char* outfilename, strlut_t &strlut )
{
  FILE *out = fopen( outfilename, "w");
  if (out == NULL) return;

  strlut_t::iterator b, e;
  for (b = strlut.begin(), e = strlut.end(); b != e; ++b)
    fprintf( out, "%08x\t%s\n", b->first, b->second );

  fclose( out );
}

