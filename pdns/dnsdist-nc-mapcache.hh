#ifndef MAPCACHE_H
#define MAPCACHE_H

#include <map>

#include "config.h"
#include "dnsdist-nc-basecache.hh"

#ifdef HAVE_NAMEDCACHE

class CdbMapCache : public BaseNamedCache {

public:
   CdbMapCache();
   ~CdbMapCache();
   void  setDebug(int debug);
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
   int iDebug;
   int iEntriesRead;
   int iCacheMode;                       // not used at present
   int iErrNum;                          // errno
   std::string strErrMsg;
   std::map<std::string, std::string> mapKeyData;

   int  loadCdbMap(std::string strCdbName);
   void wasteTimeBeforeInsert();
   void uint32_unpack(char s[4],uint32_t *u);
   int  getNum(FILE *fio, uint32_t &u32Num);
   int  getText(FILE *fio, unsigned int uBytes, std::string &strData);
   bool get(std::string key, std::string &strData);
};

#endif

#endif // MAPCACHE_H
