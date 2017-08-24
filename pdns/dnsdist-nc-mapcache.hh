#ifndef MAPCACHE_H
#define MAPCACHE_H

#include <map>
#include "dnsdist-nc-namedcache.hh"

// ----------------------------------------------------------------------------
class CdbMapCache : public NamedCache {

public:
   CdbMapCache();
   ~CdbMapCache();
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
   int  iEntriesRead;
   int iCacheMode;                       // not used at present
   std::string strErrMsg;
   std::map<std::string, std::string> mapKeyData;

   int  loadCdbMap(std::string strCdbName, int iDebug=0);
   void uint32_unpack(char s[4],uint32_t *u);
   int  getNum(FILE *fio, uint32_t &u32Num);
   int  getText(FILE *fio, unsigned int uBytes, std::string &strData);
   bool get(std::string key, std::string &strData);
};

#endif // MAPCACHE_H
