#ifndef DNSDISTNAMEDCACHE_H
#define DNSDISTNAMEDCACHE_H

#include <atomic>

#include "dnsdist-nc-namedcache.hh"
#include "dnsdist-nc-lrucache.hh"
#include "dnsdist-nc-mapcache.hh"
#include "dnsdist-nc-nocache.hh"

// ----------------------------------------------------------------------------
class DNSDistNamedCache
{
public:
  DNSDistNamedCache(const std::string& fileName, int iReqMode, size_t maxEntries, int iDebug=0);
  ~DNSDistNamedCache();
  uint64_t getMaxEntries();
  std::string   getFileName();
  uint64_t getCacheEntries();
  uint64_t getCacheHits();
  uint64_t getCdbHits();
  uint64_t getCacheMiss();
  bool     isFileOpen();
  int      lookup(const std::string& strQuery, std::string& strData);

private:
  int iDebug;
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
