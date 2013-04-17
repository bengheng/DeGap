#include <string.h>
#include <limits.h>
#include <boost/regex.hpp>
#include <boost/foreach.hpp>
#include <boost/filesystem/path.hpp>
#include <string>
#include <list>
#include <unordered_map>
#include <algorithm>
#include "utilities.h"

using namespace std;

/*!
 * Converts octal string to integer.
 * */
int convStrToInt(const char *str, int base)
{
  int shift = 0;
  int n = strlen(str) - 1;
  int retn = 0;
  int count = 0;

  // Get number of bits to shift
  while (base != 1)
  {
    base >>= 1;
    shift++;
  }

  while (n >= 0)
  {
    int i = str[n] - '0';
    retn += i * (1 << (shift * count));
    count++;
    n--;
  }

  return retn;
}

/*!
 * Removes double quotes in s. s is modified.
 * */
void zapDblQuotes(char *s)
{
  int n = strlen(s);
  int i, j;

  for (i = 0, j = 0; i <= n; ++i)
  {
    if (s[i] != '\"')
      s[j++] = s[i];
  }
}

/*!
 * Canonicalizes the paths. If path is already an absolute path
 * it is returned.
 * */
string canonicalizePaths(const char *prefix, const char *path)
{
  char buf[PATH_MAX];
  string fullpathname;

  strncpy(buf, path, PATH_MAX);
  zapDblQuotes(buf);

  if (IS_ABSOLUTE_PATH(buf))
  {
    fullpathname = buf;
  }
  else
  { // If path is a relative path, then we need to combine with prefix.

    if (strncmp(path, "(null)", 7) != 0)
    {
      boost::filesystem::path p(prefix);
      boost::filesystem::path q(buf);
      p /= q;
      fullpathname = p.normalize().string();
    }
    else
    {
      fullpathname = prefix;
    }
  }
  
  return fullpathname;
}

void printHistogram(FILE *out, list<int> &l)
{
  unordered_map< int, size_t > histogram;

  list<int>::iterator b, e;
  for( b = l.begin(), e = l.end();
      b != e; ++b )
  {
    if (histogram.find(*b) == histogram.end())
    {
      histogram[*b] = 1;
    }
    else
    {
      histogram[*b]++;
    }
  }

  unordered_map<int, size_t>::iterator hb, he;
  for (hb = histogram.begin(), he = histogram.end();
      hb != he; ++hb)
    fprintf(out, "%d -> %d\n", hb->first, hb->second);
}

/*!
 * Returns true if string str matches any of the strings in the list.
 * */
bool matchStringList(list<string *> &strlist, const char *buf)
{
  string str = buf;
  boost::regex re;
  BOOST_FOREACH(string *s, strlist)
  {
    try
    {
      re.assign(*s, boost::regex_constants::icase);
      if (boost::regex_match(str, re))
      {
        // fprintf(stderr, "DEBUG Ignoring %s\n", str.c_str());
        return true;
      }
    }
    catch(boost::regex_error &e)
    {
      fprintf(stderr, "%s is not a valid regular expression: \"%s\"\n", s->c_str(), e.what());
    }
  }

  return false;
}

/*
 * Allocates space and copies string s without double quotes, if it has any.
 * Caller must free space allocated!
 * */
char* allocCpyStrNoQuotes(const char* s)
{
  int b = 0;
  int n = 0;
  size_t l = strlen(s);
 
  if (l >= 2) {
    if (s[0] == '\"')   b = 1;
    if (s[l-1] == '\"') n = 1;
  }

  int z = l-b-n;
  assert( z != 0 );
  char* t = new char[z+1];
  if (t == NULL) return NULL;

  strncpy( t, &s[b], z );
  t[z] = 0x0;
  return t;
}
