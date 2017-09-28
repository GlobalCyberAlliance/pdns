#ifndef NOCACHE_H
#define NOCACHE_H

#include "config.h"

#include "dnsdist-nc-cdbio.hh"
#include "dnsdist-nc-namedcache.hh"

#ifdef HAVE_NAMEDCACHE

class NoCache : public NamedCache {

public:
   NoCache();
   ~NoCache();
   bool  setCacheMode(int iMode);
   bool  init(int capacity, int iCacheMode);
   bool  open(std::string strFileName);
   bool  close(void);
   int   getErrNum(void);
   std::string getErrMsg(void);
   int   getSize();
   int   getEntries();
   int   getCache(const std::string strKey, std::string &strValue);
   bool  setSize(int iEntries);
private:

};

class CdbNoCache : public NamedCache {

public:
   CdbNoCache();
   ~CdbNoCache();
   bool  setCacheMode(int iMode);
   bool  init(int capacity, int iCacheMode);
   bool  open(std::string strFileName);
   bool  close(void);
   int   getErrNum(void);
   std::string getErrMsg(void);
   int   getSize();
   int   getEntries();
   int   getCache(const std::string strKey, std::string &strValue);
   bool  setSize(int iEntries);
private:
   cdbIO cdbFH;

};

#endif

#endif // NOCACHE_H
