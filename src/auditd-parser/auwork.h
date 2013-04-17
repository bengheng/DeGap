#ifndef __AUWORK_HEADER__
#define __AUWORK_HEADER__

#include <list>
#include <unordered_map>
#include "auread.h"
#include "progfile.h"
#include "file.h"
#include "aumake.h"
#include "strhash.h"

int getEvent(
    const int nprocs,
    strlut_t &strlut,
    auparse_state_t *au,
    const SCNUM &scnum,
    ProgFile &rootprog,
    File &rootfile,
    std::list<std::string *> &ignore_paths,
    std::list<PEVENT> &events);

#endif
