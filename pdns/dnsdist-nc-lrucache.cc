
#include <malloc.h>

#include "config.h"

#include "dolog.hh"


#include "dnsdist-nc-lrucache.hh"

#ifdef HAVE_NAMEDCACHE

/*
   GCA - least recently used cache for named caches
   Note that even though lruCache is not thread safe,
   it doesn't have to be as all calls are from LUA code.

   Comment from: https://dnsdist.org/advanced/tuning.html
        "Lua processing in dnsdist is serialized by an unique lock for all threads."
   This should be ok as all calls to lruCache are thru lua with is single threaded for dnsdist
*/


lruCache::lruCache(int maxEntries)
{
  iMaxEntries = maxEntries;
  iDebug = 0;
}

lruCache::~lruCache()
{
  clearLRU();
}

void lruCache::setDebug(int debug)
{
  iDebug = debug;
}

void lruCache::clearLRU()
{
  cacheMap.clear();
  cacheList.clear();
  if(iDebug & CACHE_DEBUG::DEBUG_DISP) {
    warnlog("lruCache::clearLRU() - DEBUG - DEBUG - cleared map & list ......................... \n");
  }
  if(iDebug & CACHE_DEBUG::DEBUG_MALLOC_TRIM) {
    int iStat = malloc_trim(0);
    warnlog("bindToCDB - Releasing memory to os: %s ", iStat?"Memory Released":"NOT POSSIBLE TO RELEASE MEMORY");
  }

}

void lruCache::put(const std::string& key, const std::string& value)
{
  auto it = cacheMap.find(key);                         // get old entry in map
  cacheList.push_front(key_value_pair_t(key, value));   // put new entry in front of list
  if(it != cacheMap.end()) {
    cacheList.erase(it->second);                        // remove old entry from list
    cacheMap.erase(it);                                 // remove old entry from map
  }
  cacheMap[key] = cacheList.begin();                    // put new entry (front of list) into map

  if(cacheMap.size() > iMaxEntries) {
    auto last = cacheList.end();                        // too big, shrink
    last--;                                             // get end of list entry
    cacheMap.erase(last->first);                        // remove entry from map
    cacheList.pop_back();                               // remove end of list
  }
}

bool lruCache::get(const std::string& key, std::string &val)
{
  auto it = cacheMap.find(key);                         // find entry in map
  if(it == cacheMap.end()) {
    return(false);                                      // didn't find
  } else {                                              // move entry to top of list
      cacheList.splice(cacheList.begin(), cacheList, it->second);
      val = it->second->second;                         // return value
      return(true);
    }
}

size_t lruCache::size()
{
  return cacheMap.size();
}

// LRCCache object
LRUCache::LRUCache(int maxEntries)
{
  ptrCache = new lruCache(0);
  iDebug = 0;
}

void LRUCache::setDebug(int debug)
{
  iDebug = debug;
  ptrCache->setDebug(iDebug);
}

bool LRUCache::setCacheMode(int iMode)
{
  iCacheMode = iMode;
  return(true);
}

bool LRUCache::init(int capacity, int iCacheMode)
{
  setCacheMode(iCacheMode);
  this->iMaxEntries = capacity;
  if(ptrCache != nullptr) {
    delete ptrCache;
  }
  ptrCache = new lruCache(capacity);
  return(true);
}

bool LRUCache::get(const std::string key, std::string &val)
{
  return(ptrCache->get(key, val));
}

void LRUCache::put(const std::string key, const std::string value)
{
  ptrCache->put(key, value);
}

int LRUCache::getSize()
{
  return(iMaxEntries);
}

int LRUCache::getEntries()
{
  return(ptrCache->size());
}

int LRUCache::getErrNum()
{
  return(cdbFH.getErrNum());            // get error number from cdbIO
}

std::string LRUCache::getErrMsg()
{
  return(cdbFH.getErrMsg());            // get error message from cdbIO
}

LRUCache::~LRUCache()
{
  close();
  if(ptrCache != nullptr) {
    delete ptrCache;
  }
}

// openCDB()
// see:  http://cr.yp.to/cdb/reading.html
bool LRUCache::open(std::string strCdbName)
{
bool bStatus = false;

  bStatus = cdbFH.open(strCdbName);
  return(bStatus);
}

//  close down lru cache & free up resources
bool LRUCache::close()
{
bool bStatus = false;

  bStatus = cdbFH.close();
  if(ptrCache != nullptr) {
    delete ptrCache;
  }
  ptrCache = new lruCache(0);
  ptrCache->setDebug(iDebug);
  iMaxEntries = 0;
  iMaxEntries = 0;
  return(bStatus);
}

//  read from cache / cdb - strValue cleared if not written to
int LRUCache::getCache(const std::string strKey, std::string &strValue)
{

  if(get(strKey, strValue) == true) {           // read from cache
      if(strValue.empty()) {
        return(CACHE_HIT::HIT_CACHE_NO_DATA);   // no data in cache entry
      }
      return(CACHE_HIT::HIT_CACHE);             // data in cache entry
  }

  if(cdbFH.get(strKey, strValue) == true) {     // not in cache, read from CDB
    if(iCacheMode >= CACHE_MODE::MODE_CDB) {
       put(strKey, strValue);                   // store in cache
    }
    if(strValue.empty()) {
      return(CACHE_HIT::HIT_CDB_NO_DATA);       // no data in cdb entry
    }
    return(CACHE_HIT::HIT_CDB);                 // data in cdb entry
  }
  if(iCacheMode == CACHE_MODE::MODE_ALL) {
     put(strKey, "");                           // 'mode all' - store empty value in cache
  }
  return(CACHE_HIT::HIT_NONE);                  // ret status is 'no hit'
}



#endif
