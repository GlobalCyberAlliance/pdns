#ifndef NAMEDCACHE_H
#define NAMEDCACHE_H

#include <string>
#include "misc.hh"


enum CACHE_HIT {HIT_NONE, HIT_CDB, HIT_CACHE, HIT_CDB_NO_DATA, HIT_CACHE_NO_DATA};
enum CACHE_MODE {MODE_NONE, MODE_RPZ, MODE_ALL};
enum CACHE_TYPE {TYPE_NONE, TYPE_CDB, TYPE_MAP, TYPE_LRU};

class NamedCache {

private:
    int iMode;
public:

  NamedCache();
  virtual ~NamedCache(){}
  virtual bool setCacheMode(int iMode)=0;
  virtual bool init(int iEntries, int iCacheMode)=0;
  virtual bool open(std::string strFileName)=0;
  virtual bool close()=0;
  virtual int  getCache(std::string strKey, std::string &strValue)=0;
  virtual int  getSize(void)=0;
  virtual int  getEntries(void)=0;
  virtual std::string getErrMsg(void)=0;
  static  std::string getFoundText(int iStat);
  static  std::string getCacheModeText(int iMode);
  static  std::string getCacheTypeText(int iType);
  static  int parseCacheModeText(const std::string& strCacheType);
  static  int parseCacheTypeText(const std::string& strCacheType);

};

#endif // NAMEDCACHE_H
