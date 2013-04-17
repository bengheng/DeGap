#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <magic.h>
#include <time.h>
#include <sqlite3.h>
#include <semaphore.h>
#include <pthread.h>
#include <string>
#include <set>
#include <list>
#include <unordered_map>
#include <tuple>
#include <vector>
#include <algorithm>
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>
#include "file.h"
#include "fileinstance.h"
#include "syscall.h"
#include "process.h"
#include "program.h"
#include "utilities.h"
#include "strhash.h"
#include "db.h"

using namespace std;
using namespace boost::filesystem;

#define IS_DIR(h) \
  (h == HASH_directory || \
   h == HASH_setuid_directory || \
   h == HASH_setgid_directory || \
   h == HASH_sticky_directory || \
   h == HASH_setuid_sticky_directory || \
   h == HASH_setgid_sticky_directory || \
   h == HASH_setuid_setgid_directory || \
   h == HASH_setuid_setgid_sticky_directory)

/*!
 * File Constructor.
 * */
File::File(const File *parent, const hash_t filename_hash)
{
  parent_             = parent;
  parpath_hash_       = -1;
  fullpath_hash_      = -1;
  filename_hash_      = filename_hash;
  fileext_hash_       = -1;
  fileext_count_      = 0;
  filetype_count_     = 0;
  filetype_hash_      = HASH_Unknown;
  last_file_instance_ = NULL;
  dotdecl_            = false;
}



/*!
 * File Destructor.
 * */
File::~File()
{
  // Delete children
  BOOST_FOREACH(File *f, children_)
  { delete f; }

  pair<inode_t, set<FileInstance*>* > q;
  BOOST_FOREACH(q, instances_by_inodes_)
  { delete q.second; }

  // Delete instances
  BOOST_FOREACH(FileInstance *fi, instances_)
  { delete fi; }
}

//----------------------------------------------------------------------

/*!
 * Adds file instance.
 *
 * Note that we couldn't have simply saved the newer file instance because
 * not all syscalls would have been added yet.
 * */
void File::addFileInstances(
    list< hash_t >::iterator hashlist_end,
    list< hash_t >::iterator hashlist_itr,
    File *top,
    const hash_t fullpath_hash,
    const hash_t parpath_hash,
    list< FileInstance* > &list_fi,
    Syscall *sc,
    int depth)
{
  //fprintf(stderr, "DEBUG Trying to add %lu\n", *hashlist_itr);
  // If we're at the last token, add instance and return.
  if (hashlist_itr == hashlist_end ||
      *hashlist_itr == HASH_dot)
  {
    fullpath_hash_ = fullpath_hash;
    parpath_hash_ = parpath_hash;
    top_ = top;

    list<FileInstance*>::iterator list_fi_itr = list_fi.begin();
    while (list_fi_itr != list_fi.end())
    {
      FileInstance *fi = *list_fi_itr;
      inode_t fi_inode = fi->getInode();

      // Create FileInstances list if one doesn't exist for the inode.
      set<FileInstance *> *fi_set;
      unordered_map< inode_t, set<FileInstance *>* >::iterator it
        = instances_by_inodes_.find(fi_inode);
      if (it == instances_by_inodes_.end())
      { // No mapping. Create one.
        fi_set = new set<FileInstance *>();
        instances_by_inodes_[fi_inode] = fi_set;
      }
      else
      { // Found mapping.
        fi_set = it->second;
      }

      SCOnFile *scof = dynamic_cast<SCOnFile*>(sc);
      bool matched_fi = false;
      BOOST_FOREACH(FileInstance *fi_, *fi_set)
      {
        // Two file instances are the same if they
        // have the same inode, mode, ouid, and ogid.
        if (*fi_ == *fi)
        {
          *fi_ += *fi;
          delete fi;
          matched_fi = true;
          fi_->addSyscall(sc->getSerial(), sc);
          if (scof != NULL) scof->addFileInstance(fi_);
          break;
        }
      }

      if (matched_fi)
      {
        list_fi.erase(list_fi_itr++);
        continue;
      }

      fi->addSyscall(sc->getSerial(), sc);
      if (scof != NULL) scof->addFileInstance(fi);
      fi->setInstanceOf(this);
      instances_.insert(fi);
      fi_set->insert(fi);
      ++list_fi_itr;
    }

    return;
  }

  // Look for child with same name.
  File *child = NULL;
  BOOST_FOREACH(File *c, children_)
  {
    if (c->getNameHash() == (*hashlist_itr))
    { child = c; break; }
  }

  // If can't find child with same name, create one.
  if (child == NULL)
  {
    child = new File(this, *hashlist_itr);
    children_.push_back(child);
  }

  if (top == NULL) top = child;

  child->addFileInstances(
      hashlist_end,
      ++hashlist_itr,
      top,
      fullpath_hash,
      parpath_hash,
      list_fi, sc, depth+1);
}


//-----------------------------------------------------------------------------

bool File::operator==(const File &other) const
{ return (fullpath_hash_ == other.fullpath_hash_); }

//-----------------------------------------------------------------------------
hash_t File::getNameHash()      { return filename_hash_;  }
hash_t File::getFullpathHash()  { assert(fullpath_hash_ != -1); return fullpath_hash_;  }
hash_t File::getFiletypeHash()  { return filetype_hash_;  }
bool File::isVoid() { return (children_.empty() && instances_.empty()); }
FileInstance *File::getLastFileInstance() { return last_file_instance_; }

//-----------------------------------------------------------------------------

/*!
 * Prints file instance info if this is a leaf.
 * */
void File::pp(FILE *out, bool verbose, mode_t pp_mode, strlut_t &strlut)
{
  if (!instances_.empty() && top_ != NULL)
  {
    if ( ((pp_mode & S_IFDIR) && IS_DIR(filetype_hash_)) ||
        ((pp_mode & S_IFREG) && !IS_DIR(filetype_hash_)) )
    {
      assert( fullpath_hash_ != -1 );
      fprintf(out, "%s|%s|%s\n",
          strlut[top_->getNameHash()],
          strlut[fullpath_hash_],
          strlut[filetype_hash_]);

      if (verbose == true)
      {
        BOOST_FOREACH(FileInstance *fi, instances_)
        { fi->pp(out); }
      }
    }
  }

  BOOST_FOREACH(File *child, children_) { child->pp(out, verbose, pp_mode, strlut); }
}

//-----------------------------------------------------------------------------

void File::initLastFileInstance()
{
  BOOST_FOREACH(FileInstance *fi, instances_)
  {
    if (last_file_instance_ == NULL ||
        fi->getLastSyscallSerial() > last_file_instance_->getLastSyscallSerial())
      last_file_instance_ = fi;
  }
}

/*!
 * Purge all instances.
 * */
void File::purgeAllInstances()
{
  BOOST_FOREACH(FileInstance *fi, instances_)
  { fi->purgeSCOnFile(); delete fi; }
  instances_.clear();
  last_file_instance_ = NULL;

  // Delete instances by inode
  pair<inode_t, set<FileInstance*>* > p;
  BOOST_FOREACH(p, instances_by_inodes_) { delete p.second; }
  instances_by_inodes_.clear();
}


/*!
 * Purge old instances, which do not have the same
 * mode, uid, or gid as the last instance.
 * */
void File::purgeOldFileInstances()
{
  set<FileInstance *> saved_instances;
  BOOST_FOREACH(FileInstance *fi, instances_)
  {
    //if (fi->getMode() != last_file_instance_->getMode() ||
    //    fi->getOuid() != last_file_instance_->getOuid() ||
    //    fi->getOgid() != last_file_instance_->getOgid())
    if (*fi != *last_file_instance_)
    { fi->purgeSCOnFile(); }

    if (fi->isVoid())
    {
      //#ifdef DEBUG
      //        fprintf(stderr, "DEBUG: File         purge instance %08x "\
      //            "[inode %d mode %04o ouid %d ogid %d]\n",
      //            fi, fi->getInode(), fi->getMode(), fi->getOuid(), fi->getOgid());
      //#endif
      delete fi;
    }
    else
    { saved_instances.insert(fi); }
  }
  instances_.clear();
  instances_ = saved_instances;
}

/*
 * Dumps data to database.
 * 1. Prepare last file instance 
 * 2. Purges old file instances
 * */
void File::dumpDB( sqlite3* conn,
    strlut_t &strlut,
    list<string *> &ignore_paths,
    list<string *> &ignore_types )
{
  //fprintf( stderr, "DEBUG Dumping %s %s %d instances\n",
  //    strlut[filename_hash_], strlut[filetype_hash_], instances_.size() );

  if (!instances_.empty())
  {
    if(matchStringList(ignore_paths, strlut[fullpath_hash_]) ||
        matchStringList(ignore_types, strlut[filetype_hash_]))
    {
      // purge all instances if path or type is ignored.
      purgeAllInstances();
    }
    else
    {
      initLastFileInstance();
      assert(last_file_instance_ != NULL);
      purgeOldFileInstances();

      beginTransaction( conn );
      sqlite3_int64 rid = insertResource( conn,
          last_file_instance_->getInode(), 
          strlut[fullpath_hash_],
          strlut[fileext_hash_] );
      last_file_instance_->dumpDB( conn, strlut, rid );
      endTransaction( conn );
    }
  }

  // Recurse
  list<File *> saved_children;
  BOOST_FOREACH(File *child, children_)
  {
    child->dumpDB(conn, strlut, ignore_paths, ignore_types);
    if (child->isVoid()) { delete child; }
    else                 { saved_children.push_back(child); }
  }
  children_.clear();
  children_ = saved_children;
}


//-----------------------------------------------------------------------------

/*
 * Dumps data to DOT file.
 * 1. Prepare last file instance 
 * 2. Purges old file instances
 * */
void File::dumpDot(
    FILE *out,
    strlut_t &strlut,
    list<string *> &ignore_paths,
    list<string *> &ignore_types )
{
  //fprintf( stderr, "DEBUG Dumping %s %s %d instances\n",
  //    strlut[filename_hash_], strlut[filetype_hash_], instances_.size() );

  if (!instances_.empty())
  {
    if(matchStringList(ignore_paths, strlut[fullpath_hash_]) ||
        matchStringList(ignore_types, strlut[filetype_hash_]))
    {
      // purge all instances if path or type is ignored.
      purgeAllInstances();
    }
    else
    {
      initLastFileInstance();
      assert(last_file_instance_ != NULL);
      purgeOldFileInstances();

      /*
      sqlite3_int64 rid = insertResource( conn,
          last_file_instance_->getInode(), 
          strlut[fullpath_hash_],
          strlut[fileext_hash_] );
      */
      last_file_instance_->dumpDot( out, strlut );

    }
  }

  // Recurse
  list<File *> saved_children;
  BOOST_FOREACH(File *child, children_)
  {
    child->dumpDot(out, strlut, ignore_paths, ignore_types);
    if (child->isVoid()) { delete child; }
    else                 { saved_children.push_back(child); }
  }
  children_.clear();
  children_ = saved_children;
}

void File::dumpDotDecl(FILE *out, strlut_t &strlut)
{
  if (dotdecl_ == false) {
    fprintf(out, "%lu [shape=\"box\" label=\"%s\"]\n",
        fullpath_hash_, strlut[fullpath_hash_]);
    dotdecl_ = true;
  }
}

//-----------------------------------------------------------------------------

struct getSCIDs
{
  vector< tuple<uid_t, gid_t, uid_t, gid_t, uid_t, gid_t> > *v_;
  getSCIDs(vector< tuple<uid_t, gid_t, uid_t, gid_t, uid_t, gid_t> > *v) : v_(v) {}
  void operator() (pair<serial_t, Syscall *> p)
  {
    Syscall *sc = p.second;

    tuple<uid_t, gid_t, uid_t, gid_t, uid_t, gid_t> t = make_tuple(
        sc->getEuid(), sc->getEgid(),
        sc->getSuid(), sc->getSgid(),
        sc->getUid(), sc->getGid());

    vector< tuple<uid_t, gid_t, uid_t, gid_t, uid_t, gid_t> >::iterator b, e;
    for (b = v_->begin(), e = v_->end(); b != e; ++b)
    {
      if (*b == t) break;
    }

    if (b == e)
      v_->push_back(t);
  }
  void setCaller(FileInstance *fi) {}
};



/*!
 * Expand mode into textual form.
 * */
char* expandMode(mode_t mode, char *mode_str)
{
  char suid = '-';
  char sgid = '-';

  if (mode & S_IXUSR)
    suid =  ((mode & S_ISUID) ? 's' : 'x');
  else if (mode & S_ISUID)
    suid = 'S';

  if (mode & S_IXGRP)
    sgid =  ((mode & S_ISGID) ? 's' : 'x');
  else if (mode & S_ISGID)
    sgid = 'S';

  mode_str[0] = S_ISDIR(mode) ? 'd' : '-';
  mode_str[1] = mode & S_IRUSR ? 'r' : '-';
  mode_str[2] = mode & S_IWUSR ? 'w' : '-';
  mode_str[3] = suid;
  mode_str[4] = mode & S_IRGRP ? 'r' : '-';
  mode_str[5] = mode & S_IWGRP ? 'w' : '-';
  mode_str[6] = sgid;
  mode_str[7] = mode & S_IROTH ? 'r' : '-';
  mode_str[8] = mode & S_IWOTH ? 'w' : '-';
  mode_str[9] = mode & S_IXOTH ? 'x' : '-';
  mode_str[10] = '\0';
  return mode_str;
}


void File::printTree(FILE *out, strlut_t &strlut, int level)
{

  for (int n = 0; n < level; ++n) fprintf(out, "\t");
  if (instances_.empty())
  {
    fprintf(out, "[.] \"%s\"\n", strlut[filename_hash_]);
  }
  else
  {
    char mode_str[11];

    bool isDir = IS_DIR(filetype_hash_);
    fprintf(out, "[%c, %d] %s",
        isDir ? '+' : '-',
        instances_.size(),
        isDir ? "" : (string(",")+string(strlut[filetype_hash_])).c_str());

    // Prints file real uid, gid, and mode
    fprintf(out, ",lfi(mode=%06o)",
        last_file_instance_->getMode());

    // Prints mode and required mode tuples for each instance.
    BOOST_FOREACH(FileInstance *fi, instances_)
    {
      fprintf(out, ",fimode=%s(ouid=%d,ogid=%d)",
          expandMode(fi->getMode(), mode_str),
          fi->getOuid(), fi->getOgid());

      vector< tuple<uid_t, gid_t, uid_t, gid_t, uid_t, gid_t> > v;
      fi->for_each_syscall(getSCIDs(&v));

      tuple<uid_t, gid_t, uid_t, gid_t, uid_t, gid_t> t;
      BOOST_FOREACH(t, v)
      {
        fprintf(out, "<euid=%d,egid=%d,suid=%d,sgid=%d,uid=%d,gid=%d>",
            get<0>(t), get<1>(t), get<2>(t), get<3>(t), get<4>(t), get<5>(t));
      }
    }

    assert(fullpath_hash_ != -1);
    fprintf(out, "\t\"%s\"\n", strlut[fullpath_hash_]);
  }

  BOOST_FOREACH(File *f, children_)
  { f->printTree(out, strlut, level+1); }
}

