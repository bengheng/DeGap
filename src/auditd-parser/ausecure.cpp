#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sqlite3.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include <boost/tokenizer.hpp>
#include <iostream>
#include <fstream>
#include <list>
#include <unordered_map>
//#include <google/heap-profiler.h>
#include "aumake.h"
#include "db.h"

using namespace std;
using namespace boost::filesystem;

void printUsage(char **argv)
{
  fprintf(stdout, "Usage: %s [-l] "\
      "[-b <basepath>] " \
      "[-a <auditd logfiles>] " \
      "[-i <ignore_paths>] " \
      "[-t <ignore_types>] " \
      "-p <passwd> " \
      "-g <group>\n", argv[0]);
}

//-----------------------------------------------------------------------------

/*!
 * Loads ignores. Provides a second chance to input a filename if
 * the first try fails.
 * */
void loadIgnores(path &fname_ignore, list<string *> &ignores)
{
  if (fname_ignore.empty()) return;

  ifstream file;
  file.open(fname_ignore.string().c_str(), ifstream::in);
  if (file.fail())
  {
    cout << "Enter name of file containing ignore list: ";
    cin >> fname_ignore;
    file.open(fname_ignore.string().c_str(), ifstream::in);
  }

  string line;
  boost::char_separator<char> sep("|");
  while (getline(file, line))
  { ignores.push_back(new string(line)); }

  file.close();
}

//-----------------------------------------------------------------------------

/*!
 * Returns true if file exists.
 * */
bool fileExists(path &p)
{
  struct stat buf;
  if (stat(p.string().c_str(), &buf) != 0)
  {
    fprintf(stderr, "Error \"%s\": %s\n",
        p.string().c_str(), strerror(errno));
    return false;
  }
  return true;
}

/*!
 * Returns word length of machine, either 32 or 64, or -1 on error.
 * */
int getMachineWordLength()
{
  struct utsname buf;
  if (uname(&buf) != 0) return -1;
  if (strcmp(buf.machine, "x86_64") == 0)   return 64;
  else if(strcmp(buf.machine, "i686") == 0) return 32;
  return 0;
}

/*!
 * Make sure all required files exist.
 * */
bool checkArgs(
    path &fname_ignore_paths,
    path &fname_ignore_types,
    path &fname_out )
{
  if (!fname_ignore_paths.empty() && !fileExists(fname_ignore_paths)) {
    fprintf(stderr, "Missing path ignore file.\n");
    return false;
  }

  if (!fname_ignore_types.empty() && !fileExists(fname_ignore_types)) {
    fprintf(stderr, "Missing type ignore file.\n");
    return false;
  }

  if (fname_out.empty() || !fileExists(fname_out)) {
    fprintf(stderr, "Missing database/dot output file.\n");
    return false;
  }

  return true;
}

/*!
 * Get required arguments. The filenames are prepended with the base path.
 * */
void getArgs(
    int  argc,
    char **argv,
    char ***audit_logs,
    path &base_path,
    path &fname_ignore_paths,
    path &fname_ignore_types,
    path &fname_out)
{
  int c, n;
  char *pch;
  list<path*> aulogs;
  path fname_ignore_paths_;
  path fname_ignore_types_;
  path fname_out_;

  while ((c = getopt(argc, argv, "a:b:i:t:d:")) != -1)
  {
    switch (c)
    {
      case 'a':
        pch = strtok(optarg, ",");
        while (pch != NULL)
        {
          aulogs.push_back(new path(pch));
          pch = strtok(NULL, ",");
        }

        break;
      case 'b': base_path = optarg;					  break;
      case 'i': fname_ignore_paths_ = optarg; break;
      case 't': fname_ignore_types_ = optarg; break;
      case 'd': fname_out_ = optarg;            break;
      case '?':
                if (optopt == 'b' || optopt == 'a'
                    || optopt == 'i' || optopt == 't'
                    || optopt == 'd')
                  fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                if (isprint(optopt))
                  fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                  fprintf(stderr, "Unknown option character `\\x%x'.\n",
                      optopt);
      default:
                fprintf(stderr, "Unrecognized option.\n");
                abort();
    }
  }

  // Prepend logs with base_path
  n = 0;
  *audit_logs = new char*[aulogs.size() + 1];
  BOOST_FOREACH(path *p, aulogs)
  {
    path abspath = base_path / *p;
    abspath.normalize();
    (*audit_logs)[n] = new char[abspath.string().size() + 1];
    strcpy( (*audit_logs)[n], abspath.string().c_str());
    delete p;
    n++;
  }
  (*audit_logs)[n] = NULL;

  if (!base_path.empty())
  {
    // Prepend paths with base_path
    if (!fname_ignore_paths_.empty()) fname_ignore_paths = base_path / fname_ignore_paths_;
    if (!fname_ignore_types.empty())  fname_ignore_types = base_path / fname_ignore_types_;
    if (!fname_out_.empty())            fname_out = base_path / fname_out_;
  }

  // Normalize paths
  if (!fname_ignore_paths.empty())  fname_ignore_paths.normalize();
  if (!fname_ignore_types.empty())  fname_ignore_types.normalize();
  if (!fname_out.empty())             fname_out.normalize();
}

/*!
 * De-allocate memory used for storing log names.
 * */
void freeAuditLogNames(char ** audit_logs)
{
  if (audit_logs)
  {
    int n = 0;
    while (audit_logs[n] != NULL) delete [] audit_logs[n++];
    delete [] audit_logs;
  }
}

/*!
 * Writes to database.
 * */
static void write2Db( path& fname_db,
    strlut_t& strlut,
    File* rootfile, 
    list<string*> &ignore_paths,
    list<string*> &ignore_types )
{
  sqlite3* conn;
  sqlite3_open( fname_db.string().c_str(), &conn);
  prepareDb( conn );
  rootfile->dumpDB(conn, strlut, ignore_paths, ignore_types );
  finalizeDb();
  sqlite3_close(conn);
}

void mkModel(strlut_t &strlut,
    path &base_path,
    File *rootfile,
    ProgFile *rootprog,
    path &fname_out,
    list<string*> &ignore_paths,
    list<string*> &ignore_types)
{
  // Write filenames to file.
  path fnamep = base_path / "filenames.dat";
  fnamep.normalize();
  FILE *fnames = fopen(fnamep.string().c_str(), "w");
  if (fnames == NULL)
  {
    fprintf(stderr, "Cannot open \"%s\" for writing. %s\n",
        fnamep.string().c_str(), strerror(errno));
  }
  else
  {
    rootfile->pp(fnames, false, S_IFREG|S_IFDIR, strlut);
    fflush(fnames);
    fclose(fnames);
  }

  // This is printed out for reference.
  printStrHash( "./strhash.txt", strlut );


#ifdef USE_DB
  fprintf(stderr, "DEBUG Writing to database...\n");
  write2Db( fname_out, strlut, rootfile, ignore_paths, ignore_types );
  fprintf(stderr, "DEBUG Done writing to database.\n");
#else
  FILE *dot = fopen(fname_out.string().c_str(), "w");
  fprintf(dot, "strict digraph {\n");
  fprintf(dot, "\trankdir=LR\n");
  rootprog->dumpDot(dot, strlut);
  rootfile->dumpDot(dot, strlut, ignore_paths, ignore_types);
  fprintf(dot, "}\n");
  fclose(dot);
#endif


  path ftreep = base_path / "filetree.dat";
  ftreep.normalize();
  FILE *ftree = fopen(ftreep.string().c_str(), "w");
  assert(ftree != NULL);
  rootfile->printTree(ftree, strlut, 0);
  fclose(ftree);
}


int main(int argc, char** argv)
{
  //HeapProfilerStart();

  char **audit_logs = NULL;
  path base_path,
       fname_ignore_paths,
       fname_ignore_types,
       fname_out;
  unordered_map<long, char*> strlut; // global string lookup table

  // Get input arguments
  getArgs(argc, argv,
      &audit_logs,
      base_path,
      fname_ignore_paths,
      fname_ignore_types,
      fname_out);

  if (checkArgs( fname_ignore_paths, fname_ignore_types, fname_out ) == false)
  {
    freeAuditLogNames(audit_logs);
    printUsage(argv);
    return 0;
  }

  // Gets machine word length
  SCNUM scnum;
  switch( getMachineWordLength() )
  {
    case -1:
      fprintf(stderr, "FATAL Cannot determine machine word length!\n");
      freeAuditLogNames(audit_logs);
      return 0;
    case 32:
      scnum.__NR_open = 5;
      scnum.__NR_clone = 120;
      scnum.__NR_fork = 2;
      scnum.__NR_vfork = 190;
      scnum.__NR_execve = 11;
      break;
    case 64:
      scnum.__NR_open = 2;
      scnum.__NR_clone = 56;
      scnum.__NR_fork = 57;
      scnum.__NR_vfork = 58;
      scnum.__NR_execve = 59;
      break;
  }

  // Init string lookup table
  getStrHash(strlut, "Unknown");

  // Get lists of ignore paths/types.
  list<string *> ignore_paths, ignore_types;
  if (!fname_ignore_paths.empty()) loadIgnores(fname_ignore_paths, ignore_paths);
  if (!fname_ignore_types.empty()) loadIgnores(fname_ignore_types, ignore_types);

  ProgFile *rootprog = new ProgFile(getStrHash(strlut, ""));
  File *rootfile     = new File(NULL, getStrHash(strlut, "/"));
  set<Syscall*> syscalls;
  aumake((const char **) audit_logs,
      scnum, strlut, *rootprog, *rootfile, ignore_paths, syscalls);

  mkModel( strlut, base_path, rootfile, rootprog,
      fname_out, ignore_paths, ignore_types);

  // Free memory
  BOOST_FOREACH(string* s, ignore_paths) { delete s; }
  BOOST_FOREACH(string* s, ignore_types) { delete s; }
  pair<long, char*> lutp;
  BOOST_FOREACH(lutp, strlut) { delete [] lutp.second; }
  freeAuditLogNames(audit_logs);
  delete rootprog;
  delete rootfile;
  BOOST_FOREACH( Syscall* sc, syscalls )
  { delete sc; }
  audestroy();

  //HeapProfilerStop();
}
