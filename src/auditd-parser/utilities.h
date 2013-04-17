#ifndef __AUUTILITIES_HEADER__
#define __AUUTILITIES_HEADER__

#include <math.h>
#include <string>
#include <list>

// #ifdef __NR_open
// #undef __NR_open
// #endif
// #ifdef __NR_execve
// #undef __NR_execve
// #endif
// 
// #define __NR_open 2
// #define __NR_execve 59

#define IS_ABSOLUTE_PATH(p) (strlen(p) > 0 && p[0] == '/')

typedef struct
{
  int __NR_open;
  int __NR_clone;
  int __NR_fork;
  int __NR_vfork;
  int __NR_execve;
} SCNUM, *PSCNUM;

int convStrToInt(const char *str, int base);
void zapDblQuotes(char *s);
std::string choppa(const std::string &t, const std::string &ws);
std::string canonicalizePaths(const char *prefix, const char *path);


/*!
 * Computes the mean for a std::list of integers.
 * */
template <class T>
float calcMean(std::list<T> &l)
{
  T sum = 0;
  typename std::list<T>::iterator b, e;
  for (b = l.begin(), e = l.end();
      b != e; ++b)
    sum += *b;

  return ((float) sum / (float) l.size());
}


/*!
 * Computes the variance for a std::list of integers,
 * given it's mean.
 * */
template <class T>
float calcVariance(std::list<T> &l, float mean)
{
  float diff;
  float sum = 0;
  typename std::list<T>::iterator b, e;
  for (b = l.begin(), e = l.end();
      b != e; ++b)
  {
    diff = ((*b) - mean);
    sum += (diff * diff);
  }

  return (sum / (l.size() - 1));
}

/*!
 * Computes the Pearson's correlation between two integer std::lists.
 * */
template <class T>
float calcCorrelations(std::list<T> &x, std::list<T> &y)
{
  assert(x.size() == y.size());

  float x_mean = calcMean<T>(x);
  float y_mean = calcMean<T>(y);
  float x_stddev = sqrt( calcVariance<T>(x, x_mean) );
  float y_stddev = sqrt( calcVariance<T>(y, y_mean) );

  float x_val;
  float y_val;
  float sum = 0;
  typename std::list<T>::iterator bx, by;
  for (bx = x.begin(), by = y.begin();
    bx != x.end() && by != y.end(); ++bx, ++by)
  {
    x_val = (*bx - x_mean) / x_stddev;
    y_val = (*by - y_mean) / y_stddev;

    sum += ( x_val * y_val );
  }

  return ( sum / (x.size() - 1) );
}

void printHistogram(FILE *out, std::list<int> &l);

bool matchStringList(std::list<std::string *> &strlist, const char* buf);
char* allocCpyStrNoQuotes(const char* s);

#endif
