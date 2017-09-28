#ifndef LRUCACHE_H
#define LRUCACHE_H

#include <fcntl.h>
#include <unistd.h>
#include <cdb.h>
#include <map>
#include <unordered_map>

#include "config.h"

#include "dnsdist-nc-cdbio.hh"
#include "dnsdist-nc-namedcache.hh"

#ifdef HAVE_NAMEDCACHE

class lruCache {
public:
  typedef typename std::string keyType;
  typedef typename std::string valueType;
  typedef typename std::pair<keyType, valueType> key_value_pair_t;
  typedef typename std::list<key_value_pair_t>::iterator list_iterator_t;
  lruCache(size_t=0);
  ~lruCache();
  void put(const std::string& key, const std::string& value);
  bool get(const std::string& key, std::string &val);
  size_t size();
private:
  std::list<key_value_pair_t> cacheList;                // front is most recent use
  std::unordered_map<keyType, list_iterator_t> cacheMap;  // key with ptr to list entry
  size_t iMaxEntries;                                   // max entries to allow
};

class LRUCache : public NamedCache  {

public:

  LRUCache();
  ~LRUCache();
  bool setCacheMode(int iMode);
  bool init(int capacity, int iCacheMode);
  int  getSize();
  int  getErrNum(void);
  std::string getErrMsg(void);
  bool open(std::string strFileName);
  bool close();
  int  getCache(const std::string strKey, std::string &strValue);
  int  getEntries();


private:
  int iMaxEntries;
  int iCacheMode;       // CACHE::NONE, CACHE::RPZ, CACHE::ALL
  cdbIO cdbFH;
  lruCache *ptrCache;
  void put(const std::string key, const std::string value);
  bool get(const std::string key, std::string &val);
};

#endif

#endif // LRUCACHE_H
