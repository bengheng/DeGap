#ifndef __AUPROGRAM_HEADER__
#define __AUPROGRAM_HEADER__

#include <sqlite3.h>
#include <sys/types.h>
#include "strhash.h"

//===============
// Program Class
//===============

class Program
{
  public:
    Program(const hash_t comm_hash, const hash_t exe_hash);
    ~Program();
    Process * mkProcess(const pid_t pid);
    Process * getProcess(const pid_t pid);
    std::unordered_map<pid_t, Process *> &getProcesses() { return procs_; };
    void getAllProcesses(std::set<Process *> &procs);
    hash_t getCommHash();
    hash_t getExeHash();
//    const char * getName();
    size_t       getNumProcs();
    void pp(FILE *out, strlut_t& strlut);
    void ppFile(FILE *out, strlut_t& strlut);
    void getShortlist(std::set<File *> &shortlist);

    void purgeSyscalls(std::set<Syscall *> &bad);

    template <class F> void forEachProcess(F f)
    { for_each(procs_.begin(), procs_.end(), f); }

    sqlite3_int64 dumpDB( sqlite3 *conn, strlut_t &strlut );

    void dumpDot( FILE *out, strlut_t &strlut);
    void dumpDotDecl( FILE *out, strlut_t &strlut );

  private:
    bool        dotdecl_;
    hash_t      comm_hash_;
    hash_t      exe_hash_;
    std::unordered_map<pid_t, Process *> procs_;
};

/************
 * FUNCTORS *
 ************/

/*!
 * Returns true if same program.
 * */
struct cmpProg
{
  hash_t comm_hash_;
  hash_t exe_hash_;
  cmpProg(hash_t comm_hash, hash_t exe_hash)
    : comm_hash_(comm_hash), exe_hash_(exe_hash) {}
  bool operator()(Program *prog) const
  {
    return ( (comm_hash_ == prog->getCommHash())
        && (exe_hash_ == prog->getExeHash()) );
  }
};

/*!
 * Returns true if has process with pid.
 * */
struct getProcWithPid
{
  int pid_;
  Process **proc_;
  
  getProcWithPid(int pid, Process **proc)
    : pid_(pid), proc_(proc) {}
  bool operator()(Program *prog) const
  {
    *proc_ = prog->getProcess(pid_);
    return (*proc_ != NULL);
  }
};

/*!
 * Prints program and its processes.
 * */
struct ppProg {
  strlut_t* strlut_;
  ppProg(strlut_t* strlut) : strlut_(strlut) {}
  void operator() (Program *prog) const
  {
    prog->pp(stdout, *strlut_);
  }
};

/*!
 * Deletes program.
 * */
struct delProg {
  delProg() {}
  void operator() (Program *prog) const
  {
    delete prog;
  }
};


#endif
