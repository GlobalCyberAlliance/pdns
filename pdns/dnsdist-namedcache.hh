#ifndef DNSDISTNAMEDCACHE_H
#define DNSDISTNAMEDCACHE_H

#include <atomic>

#include "config.h"

#include "dnsdist-nc-namedcache.hh"
#include "dnsdist-nc-lrucache.hh"
#include "dnsdist-nc-lrucache2.hh"
#include "dnsdist-nc-mapcache.hh"
#include "dnsdist-nc-nocache.hh"

// ----------------------------------------------------------------------------
// Seth - GCA - named cache - 8/28/2017
//  Notes:
//
//      DNSDistNamedCache(filename, iReqMode, maxEntries, iDebug)
//              fileName - entire path name to cdb file.
//              iReqMode - named cache mode to use
//                  CACHE_TYPE::TYPE_LRU2 - LRU cache, with own doubly linked list
//                  CACHE_TYPE::TYPE_LRU - LRU cache, with std library
//                  CACHE_TYPE::TYPE_MAP - Load entire cdb into map cache
//                  CACHE_TYPE::TYPE_NONE - No cache, just lookup cdb directly
//              maxEntries - maximum amount of LRU entries to store in cache
//              iDebug - > 0 if printing out debugging statements.
//
//      getFileName() - get current cdb file used by the object
//
//      getCacheEntries() - get number of entries currently in cache
//
//      getCacheHits() - get total number of cache matching hits
//
//      getCacheMiss() - get total number of cache misses
//
//      isFileOpen() - return true in cdb file successfully opened
//
//      lookup(strQuery, strData) - return state of lookup
//                               CACHE_HIT::HIT_NONE          - 0 (match not found)
//                               CACHE_HIT::HIT_CDB           - 1 (match found in cdb file, data field not empty)
//                               CACHE_HIT::HIT_CACHE         - 2 (match found in cache, data field not empty)
//                               CACHE_HIT::HIT_CACHE_NO_DATA - 3 (match found in cache, empty data field)
//                               CACHE_HIT::HIT_CDB_NO_DATA   - 4 (match found in cdb file, empty data field)
//              strQuery - the dns name to lookup
//              strData  - return string with contents of cdb entry, else empty string
//
//       reset() - reset the object to be that of type none.
// ----------------------------------------------------------------------------

#ifdef HAVE_NAMEDCACHE

class DNSDistNamedCache
{
public:
  DNSDistNamedCache(const std::string& fileName, const std::string& strReqType, const std::string& strReqMode, size_t maxEntries, int iDebug=0);
  ~DNSDistNamedCache();
  bool init(const std::string& fileName, const std::string& strReqType, const std::string& strReqMode, size_t maxEntries, int iDebug=0);
  uint64_t getMaxEntries();
  std::string   getFileName();
  int getErrNum();
  std::string   getErrMsg();
  uint64_t getCacheEntries();
  uint64_t getCacheHits();
  uint64_t getCacheHitsNoData();
  uint64_t getCdbHits();
  uint64_t getCdbHitsNoData();
  uint64_t getCacheMiss();
  void     resetCounters();
  bool     isFileOpen();
  int      lookup(const std::string& strQuery, std::string& strData);
  bool     reset();
  std::string getCacheTypeText(bool bLoadBindMode = false);
  std::string getCacheModeText();
  time_t getCreationTime();
  time_t getCounterResetTime();
  static int parseCacheTypeText(const std::string& strCacheType);
  static int parseCacheModeText(const std::string& strCacheMode);


private:
  int iDebug;
  int iCacheType;
  int iCacheMode;
  std::string strFileName;
  size_t uMaxEntries;
  NamedCache *nc;
  bool bOpened;
  std::atomic<uint64_t> cacheHits{0};
  std::atomic<uint64_t> cacheHitsNoData{0};
  std::atomic<uint64_t> cdbHits{0};
  std::atomic<uint64_t> cdbHitsNoData{0};
  std::atomic<uint64_t> cacheMiss{0};
  time_t tCreation;
  time_t tCounterReset;
};

#endif

#endif // DNSDISTNAMEDCACHE_H
