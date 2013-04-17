#ifndef __STRHASH_HEADER__
#define __STRHASH_HEADER__

#include <list>
#include <unordered_map>


// Pre-computed hashes
#define HASH_0                                0UL                     // ""
#define HASH_null                             1404164585001UL         // "(null)"
#define HASH_dot                              46UL                    // "."
#define HASH_Unknown                          377642479778798UL       // "Unknown"
#define HASH_None                             165410661UL             // "None"
#define HASH_empty                            27342420601UL           // "empty"

#define HASH_symbolic_link                    8059656738617012956UL   // "symbolic link"

#define HASH_root                             47UL                    // "/"
#define HASH_directory                        7265374023358085497UL   // "directory"
#define HASH_setuid_directory                 7265628661892067977UL   // "setuid directory"
#define HASH_setgid_directory                 7265628661877387913UL   // "setgid directory"
#define HASH_sticky_directory                 7265628918094854089UL   // "sicky directory"
#define HASH_setuid_sticky_directory          15489201845444331139UL  // "setuid sticky directory"
#define HASH_setgid_sticky_directory          15489201845444330691UL  // "setgid sticky directory"
#define HASH_setuid_setgid_directory          15489201589226864963UL  // "setuid setgid directory"
#define HASH_setuid_setgid_sticky_directory   8388402096517178146UL   // "setuid setgid sticky directory"

typedef long hash_t;
typedef std::unordered_map<hash_t, char*> strlut_t;

hash_t calcStrHash(const char* s, const std::size_t len);

hash_t getBufHash(strlut_t &strlut, const char *buf, const std::size_t nb);

hash_t getStrHash(strlut_t &strlut, const char *str);

void splitStrToHashList(
    strlut_t &strlut,
    char *str,
    const char *delim,
    std::list< hash_t > &hashlist);

void splitPathToHashList(
    strlut_t &strlut,
    char *str,
    const char *delim,
    std::list< hash_t > &hashlist);

void printStrHash( const char* outfilename, strlut_t &strlut );

#endif
