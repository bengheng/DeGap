#ifndef __AUPROCESS_HEADER__
#define __AUPROCESS_HEADER__

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <boost/tokenizer.hpp>
#include <set>
#include <list>
#include <vector>
#include <unordered_map>
#include <string>
#include "strhash.h"
#include "sqlite3.h"

typedef boost::tokenizer<boost::char_separator<char> > tokenizer;
typedef unsigned long serial_t;

// Forward declaration
class Syscall;
class File;

//====================
// Process Class
//====================

// Forward declaration
class Program;

/*!
 * ProcInstance is an instantiation of a process with new Pid.
 * */
class Process
{
  public:
    Process(Program *instance_of, const pid_t pid);
    void addParent(Process *parent);
    void addChild(Process *child);
    void pp(FILE *out);
    pid_t getPid();
    Program *getInstanceOf();
    size_t getNumSyscalls();
    void addSyscall(serial_t serial, Syscall *sc);
    void purgeSyscalls(std::set<Syscall *> &bad);
    void purgeSyscall(Syscall *bad);

    template <class F>
      void forEachSyscall(F f)
      { for_each(syscalls_.begin(), syscalls_.end(), f); }

    std::unordered_map<pid_t, Process *> &getParents()  { return parents_;  }
    std::unordered_map<pid_t, Process *> &getChildren() { return children_; }

    void ppFile(FILE *out, strlut_t &strlut);

    sqlite3_int64 dumpDB( sqlite3* conn, strlut_t& strlut );
    void dumpDot( FILE *out, strlut_t &strlut );

  private:
    bool    dotdone_;
    pid_t   pid_;
    bool    zombified_;
    Program *instance_of_;
    std::unordered_map<pid_t, Process *> parents_;
    std::unordered_map<pid_t, Process *> children_;
    std::unordered_map<serial_t, Syscall *> syscalls_;
};


#endif
