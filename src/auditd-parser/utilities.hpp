#include <assert.h>
#include <list>

using namespace std;

/*!
 * Computes the longest common prefix for a list of file strings.
 *
 * T is the type for each string. It must be iterable.
 *
 * U is the type for each character/element of the string.
 * */
template<class T, class U>
void computeLongestCommonPrefix(
    list<T*> &strings,
    T &lcp,
    void (*append)(T&, U))
{
  assert(strings.size() > 0);

  T prefix, tmp_prefix;

  typename list<T*>::iterator pb, pe;
  pb = strings.begin();
  pe = strings.end();

  prefix = **(pb++);
  for (; pb != pe; ++pb)
  {
    tmp_prefix.clear();

    // Compare the string tokens
    typename T::iterator b1, e1, b2, e2;
    b1 = (*pb)->begin();
    e1 = (*pb)->end();
    b2 = prefix.begin();
    e2 = prefix.end();
    for (; b1 != e1 && b2 != e2; ++b1, ++b2)
    {
      // Appends the string token if they match
      if ( **b1 == **b2 ) (*append)(tmp_prefix, *b1);
      else break;
    }
    prefix.clear();
    prefix = tmp_prefix;
  }
  lcp = prefix;
}

/*!
 * Reverses pin and stores in pout.
 * */
  template<class T, class U>
void reversePath(T &pin, T &pout, void (*append)(T&, U) )
{
  pout.clear();

  typename T::iterator pb = pin.begin();
  typename T::iterator pe = pin.end();
  do
  {
    if (pb == pe) break;
    --pe;
    (*append)(pout, *pe);
  } while (true);
}

/*!
 * Computes the longest common suffix for a list of file strings.
 * */
template<class T, class U>
void computeLongestCommonSuffix(
    list<T*> &strings,
    T &lcs,
    void (*append)(T&, U))
{
  assert(strings.size() > 0);

  T suffix, tmp_suffix;

  typename list<T*>::iterator pb, pe;
  pb = strings.begin();
  pe = strings.end();

  reversePath(**(pb++), suffix, *append);

  for (; pb != pe; ++pb)
  {
    tmp_suffix.clear();

    // Compare the string tokens in reverse
    typename T::iterator b1, e1, b2, e2;
    b1 = (*pb)->begin();
    e1 = (*pb)->end();
    b2 = suffix.begin();
    e2 = suffix.end();
    do
    {
      if (b1 == e1 || b2 == e2) break;
      --e1;

      // Appends the string token if they match
      if ( **e1 == **b2 ) (*append)(tmp_suffix, *e1);
      else break;

      ++b2;
    } while (true);

    suffix.clear();
    suffix = tmp_suffix;
  }

  // Reverse the suffix
  reversePath(suffix, lcs, *append);
}

