#ifndef __AUSSEMBLE_HEADER__
#define __AUSSEMBLE_HEADER__

#include <set>
#include <list>
#include <unordered_map>
#include "strhash.h"
#include "file.h"
#include "aumake.h"

void assemble(
    const int nprocs,
    strlut_t &strlut,
    std::list<PEVENT> &events,
    std::set<Syscall*> &syscalls,
    File &rootfile);

#endif
