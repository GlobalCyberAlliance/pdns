#ifndef DNSDISTNAMEDCACHE_H
#define DNSDISTNAMEDCACHE_H

#include <atomic>

#include "dnsdist-nc-namedcache.hh"
#include "dnsdist-nc-lrucache.hh"
#include "dnsdist-nc-mapcache.hh"
#include "dnsdist-nc-nocache.hh"

// ----------------------------------------------------------------------------
// Seth - GCA - named cache - 8/28/2017
//  Notes:
//
//      DNSDistNamedCache(filename, iReqMode, maxEntries, iDebug)
//              fileName - entire path name to cdb file.
//              iReqMode - named cache mode to use
//                  CACHE_TYPE::TYPE_LRU - LRU cache
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
//                  CACHE_HIT::HIT_CACHE - match found in cache
//                  CACHE_HIT::HIT_CDB   - match found in cdb file
//                  CACHE_HIT::HIT_NONE  - match not found
//              strQuery - the dns name to lookup
//              strData  - return string with contents of cdb entry, else empty string
//
//       reset() - reset the object to be that of type none.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
class DNSDistNamedCache
{
public:
  DNSDistNamedCache(const std::string& fileName, const std::string& strReqType, const std::string& strReqMode, size_t maxEntries, int iDebug=0);
  ~DNSDistNamedCache();
  bool init(const std::string& fileName, const std::string& strReqType, const std::string& strReqMode, size_t maxEntries, int iDebug=0);
  uint64_t getMaxEntries();
  std::string   getFileName();
  uint64_t getCacheEntries();
  uint64_t getCacheHits();
  uint64_t getCdbHits();
  uint64_t getCacheMiss();
  bool     isFileOpen();
  int      lookup(const std::string& strQuery, std::string& strData);
  bool     reset();
  std::string getCacheTypeText();
  std::string getCacheModeText();
  static int parseCacheTypeText(const std::string& strCacheType);
  static int parseCacheModeText(const std::string& strCacheMode);


private:
  int iDebug;
  int iCacheType;
  int iCacheMode;
  std::string strFileName;
  size_t uMaxEntries;
  //LRUCache lrucache;
  NamedCache *nc;
  bool bOpened;
  std::atomic<uint64_t> cache_hits{0};
  std::atomic<uint64_t> cdb_hits{0};
  std::atomic<uint64_t> cache_miss{0};
};

#endif // DNSDISTNAMEDCACHE_H
