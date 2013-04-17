/*!
 * File information is stored in the same manner as how files are laid out,
 * i.e. with directories as non-leaf nodes and files as leaf nodes.
 *
 * Each file can have multiple file instances. 
 * */

#ifndef __AUF_HEADER__
#define __AUF_HEADER__

#include <boost/tokenizer.hpp>
#include <time.h>
#include <sqlite3.h>
#include <semaphore.h>
#include <pthread.h>
#include <list>
#include <set>
#include <string>
#include <unordered_map>

#include "process.h"
#include "fileinstance.h"
#include "strhash.h"

typedef boost::tokenizer<boost::char_separator<char> > tokenizer;
typedef unsigned long serial_t;
typedef int           inode_t;

#define AV_USR 0
#define AV_GRP 3
#define AV_OTH 6
#define AV_R 0
#define AV_W 1
#define AV_X 2

#define ROOT_UID ((uid_t) 0)
#define ROOT_GID ((gid_t) 0)
#define BAD_UID ((uid_t) 0xffffffff)
#define BAD_GID ((gid_t) 0xffffffff)
#define BAD_MODE  ((mode_t) -1)
#define INVALID_MODE(m) (m == BAD_MODE)

#define IS_ROOT_UID(m) (m == ROOT_UID)

#define BAD_FILETYPE(h) \
  (h == HASH_Unknown || \
   h == HASH_None || \
   h == HASH_empty)


class File;

// Forward declaration
class Syscall;
class SCOnFile;

typedef enum
{
  RET_END = 0,
  RET_OK,
  RET_NOMATCH
} ret_t;

class File
{
  public:
    File(const File *parent, const hash_t name_hash);
    ~File();

    void addFileInstances(
        std::list<hash_t>::iterator hashlist_end,
        std::list<hash_t>::iterator hashlist_itr,
        File *top,
        const hash_t fullpath_hash,
        const hash_t parpath_hash,
        std::list<FileInstance*> &lfi,
        Syscall *sc,
        int depth);
    void dumpDB(sqlite3* conn, strlut_t &strlut,
        std::list<std::string *> &ignore_paths,
        std::list<std::string *> &ignore_types);

    void dumpDot(FILE *out,
        strlut_t &strlut,
        std::list<std::string *> &ignore_paths,
        std::list<std::string *> &ignore_types);
    void dumpDotDecl(FILE *out, strlut_t &strlut);

    FileInstance *getLastFileInstance();
    hash_t      getNameHash();
    hash_t      getFiletypeHash();
    hash_t      getFullpathHash();
    size_t      getNumCallers();
    void pp(FILE *out, bool verbose, mode_t pp_mode, strlut_t &strlut);
    void printTree(FILE *out, strlut_t &strlut, int level);
    bool operator==(const File &other) const;

  private:
    bool                    dotdecl_;
    File                    *top_;
    hash_t                  filename_hash_;
    hash_t                  fileext_hash_;
    hash_t                  parpath_hash_;  // parent path hash
    hash_t                  fullpath_hash_;
    hash_t                  filetype_hash_;

    size_t                  filetype_count_; // number of files having same type
    size_t                  fileext_count_;  // number of files having same extension
    const File              *parent_;
    std::list<File *>       children_;

    FileInstance                                              *last_file_instance_;
    std::set<FileInstance *>                                 instances_;
    std::unordered_map< inode_t, std::set<FileInstance *>* >  instances_by_inodes_;

    void initLastFileInstance();
    void purgeAllInstances();
    void purgeOldFileInstances();
    bool isVoid();
};

#endif
