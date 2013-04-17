#ifndef __AUFILEINSTANCE_HEADER__
#define __AUFILEINSTANCE_HEADER__

#include <sqlite3.h>
#include <boost/filesystem.hpp>
#include <set>
#include <string>
#include <unordered_map>
#include "process.h"

typedef unsigned long serial_t;
typedef int           inode_t;

class File;

class FileInstance
{
  public:
    FileInstance(
        const long name_hash,
        const inode_t inode,
        const mode_t mode,
        const uid_t ouid,
        const gid_t ogid);
    ~FileInstance();
    void setMode(const mode_t mode);
    void setOuid(const uid_t ouid);
    void setOgid(const gid_t ogid);
    void setInstanceOf(File *instance_of);

    long getNameHash();
    inode_t getInode();
    mode_t getMode();
    uid_t getOuid();
    gid_t getOgid();
    File *getInstanceOf();
    serial_t getLastSyscallSerial();
    size_t getNumSyscalls();
    void getSyscalls(std::set<Syscall *> &syscalls);
    void addSyscall(serial_t serial, Syscall *sc);
    void purgeSCOnFile();
    bool isVoid();

    void pp(FILE *out);

    template <class F>
      void for_each_syscall(F f)
      {
        f.setCaller(this);
        for_each(syscalls_.begin(), syscalls_.end(), f);
      }

    bool operator==(const FileInstance &rhs) const;
    bool operator!=(const FileInstance &rhs) const;
    FileInstance& operator+=(const FileInstance &rhs);

    void dumpDB( sqlite3 *conn, strlut_t& strlut, sqlite3_int64 fileid );
    void dumpDot( FILE *out, strlut_t& strlut );

  private:
    long                    name_hash_;
    File                    *instance_of_;
    inode_t                 inode_;

    // These values are obtained from auditd logs.
    // In contrast, the st_* values in file.h are obtained
    // using stat() or equivalent methods.
    mode_t                  sc_mode_;
    uid_t                   sc_uid_;
    gid_t                   sc_gid_;

    Syscall                 *last_syscall_;  
    std::unordered_map<serial_t, Syscall *> syscalls_;
};

#endif
