#ifndef NOCACHE_H
#define NOCACHE_H

#include "dnsdist-nc-cdbio.hh"
#include "dnsdist-nc-namedcache.hh"

// ----------------------------------------------------------------------------
class NoCache : public NamedCache {

public:
   NoCache();
   ~NoCache();
   bool  setCacheMode(int iMode);
   bool  init(int capacity, int iCacheMode);
   bool  open(std::string strFileName);
   bool  close(void);
   std::string getErrMsg(void);
   int   getSize();
   int   getEntries();
   int   getCache(const std::string strKey, std::string &strValue);
   bool  setSize(int iEntries);
private:
   std::string strErrMsg;
   cdbIO cdbFH;

};

// ----------------------------------------------------------------------------
class CdbNoCache : public NamedCache {

public:
   CdbNoCache();
   ~CdbNoCache();
   bool  setCacheMode(int iMode);
   bool  init(int capacity, int iCacheMode);
   bool  open(std::string strFileName);
   bool  close(void);
   std::string getErrMsg(void);
   int   getSize();
   int   getEntries();
   int   getCache(const std::string strKey, std::string &strValue);
   bool  setSize(int iEntries);
private:
   std::string strErrMsg;
   cdbIO cdbFH;

};

#endif // NOCACHE_H
