#ifndef __AUPROGFILE_HEADER__
#define __AUPROGFILE_HEADER__

/*!
 * ProgFile provides the directory structure for programs.
 * */

#include <sys/types.h>
#include <set>
#include <list>
#include <string>
#include "file.h"
#include "process.h"
#include "program.h"
#include "strhash.h"

class ProgFile
{
  public:
    ProgFile(const hash_t name_hash);
    ~ProgFile();
    void getAllProcesses(std::set<Process *> &procs);
    Process * getProcess(const pid_t pid);
    hash_t getNameHash();

    Program *addProgram(
        std::list< hash_t >::iterator hashlist_end,
        std::list< hash_t >::iterator hashlist_itr,
        const hash_t comm_hash,
        const hash_t exe_hash);
    void getShortlist(std::set<File *> &shortlist);

    void purgeSyscalls(std::set<Syscall *> &bad);

    void dumpDot( std::FILE *out, strlut_t &strlut );

  private:
    hash_t name_hash_;
    std::list<Program *>  programs_;

    const ProgFile        *top_;
    const ProgFile        *parent_;
    std::list<ProgFile *> children_;

    Program *addProgram(
        std::list< hash_t >::iterator hashlist_end,
        std::list< hash_t >::iterator hashlist_itr,
        ProgFile *top,
        const hash_t comm_hash,
        const hash_t exe_hash);
};

#endif
