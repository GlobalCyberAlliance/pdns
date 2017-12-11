#ifndef DNSDISTNAMEDCACHE_H
#define DNSDISTNAMEDCACHE_H

#include <atomic>
#include <chrono>
#include <ctime>

#include "dnsdist.hh"
#include "misc.hh"
#include "dolog.hh"
#include "config.h"
#include "gettime.hh"

#include "dnsdist-nc-basecache.hh"
#include "dnsdist-nc-lrucache.hh"
#include "dnsdist-nc-mapcache.hh"
#include "dnsdist-nc-nocache.hh"



/*
   GCA - named cache
    Notes:

        DNSDistNamedCache(filename, iReqMode, maxEntries, iDebug)
                fileName - entire path name to cdb file.
                iReqMode - named cache mode to use
                    CACHE_TYPE::TYPE_LRU2 - LRU cache, with own doubly linked list
                    CACHE_TYPE::TYPE_LRU - LRU cache, with std library
                    CACHE_TYPE::TYPE_MAP - Load entire cdb into map cache
                    CACHE_TYPE::TYPE_NONE - No cache, just lookup cdb directly
                maxEntries - maximum amount of LRU entries to store in cache
                iDebug - > 0 debugging modes.
                         & CACHE_DEBUG::DEBUG_DISP

        getFileName() - get current cdb file used by the object

        getCacheEntries() - get number of entries currently in cache

        getCacheHits() - get total number of cache matching hits

        getCacheMiss() - get total number of cache misses

        isFileOpen() - return true in cdb file successfully opened

        lookup(strQuery, strData) - return state of lookup
                                 CACHE_HIT::HIT_NONE          - 0 (match not found)
                                 CACHE_HIT::HIT_CDB           - 1 (match found in cdb file, data field not empty)
                                 CACHE_HIT::HIT_CACHE         - 2 (match found in cache, data field not empty)
                                 CACHE_HIT::HIT_CACHE_NO_DATA - 3 (match found in cache, empty data field)
                                 CACHE_HIT::HIT_CDB_NO_DATA   - 4 (match found in cdb file, empty data field)
                strQuery - the dns name to lookup
                strData  - return string with contents of cdb entry, else empty string

         reset() - reset the object to be that of type none.
*/

#ifdef HAVE_NAMEDCACHE

#define DELTA_AVG 1000



class DNSDistNamedCache
{
public:
  DNSDistNamedCache(const std::string& cacheName, const std::string& fileName, const std::string& reqType, const std::string& reqMode, size_t maxEntries, int iDebug=0);
  ~DNSDistNamedCache();
  bool init(const std::string& cacheName, const std::string& fileName, const std::string& reqType, const std::string& reqMode, size_t maxEntries);
  bool close(void);
  uint64_t getMaxEntries();
  std::string   getCacheName();
  void setCacheName(const std::string cacheName);
  std::string   getFileName();
  int getErrNum();
  std::string   getErrMsg();
  int getDebugFlags();
  uint64_t getCacheEntries();
  int      getQuerySec();
  uint64_t getCacheHits();
  uint64_t getCacheHitsNoData();
  uint64_t getCdbHits();
  uint64_t getCdbHitsNoData();
  uint64_t getCacheMiss();
  void     resetCounters();
  bool     isFileOpen();
  int      lookup(const std::string& strQuery, std::string& strData);
  int      lookupWalk(const std::string& strQuery, std::string& strData, int iWalkMode = 0, bool bDebug = false);
  bool     reset();
  std::string getCacheTypeText(bool bLoadBindMode = false);
  std::string getCacheModeText();
  time_t getCreationTime();
  time_t getCounterResetTime();
  static int parseCacheTypeText(const std::string& strCacheType);
  static int parseCacheModeText(const std::string& strCacheMode);
  std::string getNamedCacheStatusText();
  void getNamedCacheStatusTable(std::unordered_map<string, string> &tableResult);

  int iDebug;
  int iCacheType;
  int iCacheMode;
  std::string strFileName;
  size_t uMaxEntries;
  BaseNamedCache *bnc;
  bool bOpened;
  time_t tCreation;

private:
  std::string strCacheName;
  std::atomic<uint64_t> cacheHits{0};
  std::atomic<uint64_t> cacheHitsNoData{0};
  std::atomic<uint64_t> cdbHits{0};
  std::atomic<uint64_t> cdbHitsNoData{0};
  std::atomic<uint64_t> cacheMiss{0};
  std::atomic<double>   deltaLookup[DELTA_AVG];
  int deltaCount;
  time_t tCounterReset;
  class StopWatch *sw;

};


// NamedCache Table
using namedCaches_t=map<std::string, std::shared_ptr<DNSDistNamedCache>>;


extern namedCaches_t g_namedCacheTable;

extern std::atomic<std::uint16_t> g_namedCacheTempFileCount;

extern std::string g_namedCacheTempPrefix;

std::shared_ptr<DNSDistNamedCache> createNamedCacheIfNotExists(namedCaches_t& namedCaches, const string& poolName, const int iDebug=0);

extern bool deleteNamedCacheEntry(namedCaches_t& namedCachesTable, const string& findCacheName, const int iDebug=0);

extern int  swapNamedCacheEntries(namedCaches_t& namedCachesTable, const string& findCacheNameA, const string& findCacheNameB, const int iDebug=0);

extern void namedCacheLoadThread(std::shared_ptr<DNSDistNamedCache> entryCacheA, const std::string strFileName, const std::string strCacheType, const std::string strCacheMode, int iMaxEntries, const int iDebug=0);

extern void namedCacheReloadThread(const std::string& strCacheNameA,  boost::optional<int> maxEntries);
extern std::string getAllNamedCacheStatus(namedCaches_t& namedCachesTable, int iDebug = 0);

#endif

#endif // DNSDISTNAMEDCACHE_H
