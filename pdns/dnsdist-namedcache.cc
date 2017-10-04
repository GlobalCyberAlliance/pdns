#include "dnsdist-namedcache.hh"


#ifdef HAVE_NAMEDCACHE

DNSDistNamedCache::DNSDistNamedCache(const std::string& fileName, const std::string& strReqType, const std::string& strReqMode, size_t maxEntries, int debug)
{
  nc = nullptr;
  init(fileName, strReqType, strReqMode, maxEntries, debug);
}

DNSDistNamedCache::~DNSDistNamedCache()
{
  if(iDebug > 0) {
    printf("DEBUG DEBUG DEBUG - ~DNSDistNamedCache() - object DESTROYED XXXXXXXXXXXXXXXXXXXXXXXXXXXX \n");
  }
}

// ----------------------------------------------------------------------------
// reset() - reset object to type 'none'
// ----------------------------------------------------------------------------
bool DNSDistNamedCache::reset()
{
bool bStat = true;

  if(iDebug > 0) {
    printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::reset() - start \n");
  }

  iCacheType = CACHE_TYPE::TYPE_NONE;
  iCacheMode = CACHE_MODE::MODE_NONE;
  strFileName = "";
  uMaxEntries = 0;
  bOpened = false;
  tCreation = time(NULL);

  resetCounters();

  if(nc != nullptr) {
    if(iDebug > 0) {
      printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::reset() - deleting nc object \n");
      }
    delete nc;
  }
  nc = new NoCache();
  if(iDebug > 0) {
    printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::reset() - finished \n");
  }
  return(bStat);
}

// ----------------------------------------------------------------------------
// init() - initialize object - also destroys old one if it exists
// ----------------------------------------------------------------------------
bool DNSDistNamedCache::init(const std::string& fileName, const std::string& strReqType, const std::string& strReqMode, size_t maxEntries, int debug)
{
bool bStat = false;

  reset();             // reset existing object
  iDebug = debug;
  strFileName = fileName;
  uMaxEntries = maxEntries;
  bOpened = false;
  iCacheType = parseCacheTypeText(strReqType);
  iCacheMode = parseCacheModeText(strReqMode);
  if(debug > 0) {
    printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::init() - creating object XXXXXXXXXXXXXXXXXXXXXXXXXXXX \n");
    printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::init() - requested cdb file: %s \n", fileName.c_str());
    printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::init() - requested entries.: %lu \n", maxEntries);
    printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::init() - requested Type....: %s \n", NamedCache::getCacheTypeText(iCacheType).c_str());
    printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::init() - requested Mode....: %s \n", NamedCache::getCacheModeText(iCacheMode).c_str());
  }
  switch(iCacheType) {
    case CACHE_TYPE::TYPE_LRU2:
        nc = new LRUCache2();
        break;
    case CACHE_TYPE::TYPE_LRU:
        nc = new LRUCache();
        break;
    case CACHE_TYPE::TYPE_MAP:
        nc = new CdbMapCache();
        break;
    case CACHE_TYPE::TYPE_CDB:
        nc = new CdbNoCache();
        break;
    case CACHE_TYPE::TYPE_NONE:
        nc = new NoCache();
        break;
    default:
        nc = NULL;
        break;
    }

  if(nc->init(uMaxEntries, CACHE_MODE::MODE_ALL) == true) {
    if(iDebug > 0) {
      printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::init() - init nc object with max entries: %lu \n", uMaxEntries);
    }
    if(nc->open(fileName) == true) {
      bOpened = true;
    } else {
        uMaxEntries = 0;
      }
  }

  if(iDebug > 0) {
    printf("DEBUG DEBUG DEBUG - DNSDistNamedCache()::init() - cdb file opened: %s    %s \n", bOpened?"YES":"NO", fileName.c_str());
    if(bOpened == false) {
      printf("DEBUG DEBUG DEBUG - DNSDistNamedCache(::init() - Error msg: %s \n", nc->getErrMsg().c_str());
    }
  }
  if(bOpened == true) {
    bStat = true;
  }
  return(bStat);
}

// ----------------------------------------------------------------------------
// lookup() - lookup query in cache
// ----------------------------------------------------------------------------
int DNSDistNamedCache::lookup(const std::string& strQuery, std::string& strData)
{
  int iLoc = nc->getCache(strQuery, strData);
  switch(iLoc) {
    case CACHE_HIT::HIT_CDB_NO_DATA:
      cdbHitsNoData++;
      break;
    case CACHE_HIT::HIT_CACHE_NO_DATA:
      cacheHitsNoData++;
      break;
    case CACHE_HIT::HIT_CACHE:
      cacheHits++;
      break;
    case CACHE_HIT::HIT_CDB:
      cdbHits++;
      break;
    case CACHE_HIT::HIT_NONE:
      cacheMiss++;
      break;
    default:
      break;
  }
  return(iLoc);
}

// ----------------------------------------------------------------------------
// getMaxEntries() - get maximum entries in cache
// ----------------------------------------------------------------------------
uint64_t DNSDistNamedCache::getMaxEntries()
{
  return(uMaxEntries);
}

// ----------------------------------------------------------------------------
// getFileName() - get cdb filename used to load cache
// ----------------------------------------------------------------------------
std::string DNSDistNamedCache::getFileName()
{
  return(strFileName);
}

// ----------------------------------------------------------------------------
// getErrMsg() - get i/o error number (errno)
// ----------------------------------------------------------------------------
int DNSDistNamedCache::getErrNum()
{
  return(nc->getErrNum());
}
// ----------------------------------------------------------------------------
// getErrMsg() - get error message text
// ----------------------------------------------------------------------------
std::string DNSDistNamedCache::getErrMsg()
{
  return(nc->getErrMsg());
}

// ----------------------------------------------------------------------------
// getCacheEntries() - get current number of entries in cache
// ----------------------------------------------------------------------------
uint64_t DNSDistNamedCache::getCacheEntries()
{
  return(nc->getEntries());
}

// ----------------------------------------------------------------------------
// getCacheHits() - get current number of cache hits
// ----------------------------------------------------------------------------
uint64_t DNSDistNamedCache::getCacheHits()
{
  return(cacheHits);
}

// ----------------------------------------------------------------------------
// getCacheHitsNoData() - get current number of cache hits, with no data (ie. not rpz)
// ----------------------------------------------------------------------------
uint64_t DNSDistNamedCache::getCacheHitsNoData()
{
  return(cacheHitsNoData);
}

// ----------------------------------------------------------------------------
// getCdbHits() - get current number of cdb hits
// ----------------------------------------------------------------------------
uint64_t DNSDistNamedCache::getCdbHits()
{
  return(cdbHits);
}

// ----------------------------------------------------------------------------
// getCdbHitsNoData() - get current number of cdb hits, with no data (ie. not rpz)
// ----------------------------------------------------------------------------
uint64_t DNSDistNamedCache::getCdbHitsNoData()
{
  return(cdbHitsNoData);
}

// ----------------------------------------------------------------------------
// getCacheMiss() - get current number of cache misses
// ----------------------------------------------------------------------------
uint64_t DNSDistNamedCache::getCacheMiss()
{
  return(cacheMiss);
}

// ----------------------------------------------------------------------------
// resetCounts() - reset the counters
// ----------------------------------------------------------------------------
void DNSDistNamedCache::resetCounters()
{
  cacheHits = 0;
  cacheHitsNoData = 0;
  cdbHits = 0;
  cdbHitsNoData = 0;
  cacheMiss = 0;
  tCounterReset = time(NULL);
}

// ----------------------------------------------------------------------------
// isFileOpen() - return true if file open
// ----------------------------------------------------------------------------
bool DNSDistNamedCache::isFileOpen()
{
  return(bOpened);
}

std::string  DNSDistNamedCache::getCacheTypeText()
{
  return(NamedCache::getCacheTypeText(iCacheType));
}

std::string  DNSDistNamedCache::getCacheModeText()
{
  return(NamedCache::getCacheModeText(iCacheMode));
}

time_t DNSDistNamedCache::getCreationTime()
{
  return(tCreation);
}

time_t DNSDistNamedCache::getCounterResetTime()
{
  return(tCounterReset);
}

int DNSDistNamedCache::parseCacheTypeText(const std::string& strCacheType)
{
  return(NamedCache::parseCacheTypeText(strCacheType));
}

int DNSDistNamedCache::parseCacheModeText(const std::string& strCacheMode)
{
  return(NamedCache::parseCacheModeText(strCacheMode));
}

#endif
