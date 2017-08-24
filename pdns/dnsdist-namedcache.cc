// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#include "dnsdist-namedcache.hh"

// ----------------------------------------------------------------------------
// DNSDistNamedCache() - object creation
// ----------------------------------------------------------------------------
DNSDistNamedCache::DNSDistNamedCache(const std::string& fileName, int iReqMode, size_t maxEntries, int debug)
{
   if(debug > 0) {
     printf("DEBUG DEBUG DEBUG - DNSDistNamedCache() - creating object XXXXXXXXXXXXXXXXXXXXXXXXXXXX \n");
     printf("DEBUG DEBUG DEBUG - DNSDistNamedCache() - requested cdb file: %s \n", fileName.c_str());
     printf("DEBUG DEBUG DEBUG - DNSDistNamedCache() - requested entries.: %lu \n", maxEntries);
     printf("DEBUG DEBUG DEBUG - DNSDistNamedCache() - requested mode....: %s \n", NamedCache::getCacheModeText(iReqMode).c_str());
   }
   iDebug = debug;
   strFileName = fileName;
   uMaxEntries = maxEntries;
   bOpened = false;

   switch(iReqMode) {
     case CACHE_TYPE::TYPE_LRU:
        nc = new LRUCache();
        break;
     case CACHE_TYPE::TYPE_MAP:
        nc = new CdbMapCache();
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
      printf("DEBUG DEBUG DEBUG - DNSDistNamedCache() - init with max entries: %lu \n", uMaxEntries);
    }
    if(nc->open(fileName) == true) {
      bOpened = true;
    } else {
      uMaxEntries = 0;
      }
  }
  if(iDebug > 0) {
    printf("DEBUG DEBUG DEBUG - DNSDistNamedCache() - cdb file opened: %s    %s \n", bOpened?"YES":"NO", fileName.c_str());
    if(bOpened == false) {
      printf("DEBUG DEBUG DEBUG - DNSDistNamedCache() - Error msg: %s \n", nc->getErrMsg().c_str());
    }
  }

}

// ----------------------------------------------------------------------------
// ~DNSDistNamedCache() - object destruction
// ----------------------------------------------------------------------------
DNSDistNamedCache::~DNSDistNamedCache()
{
   if(iDebug > 0) {
     printf("DEBUG DEBUG DEBUG - ~DNSDistNamedCache() - object DESTROYED XXXXXXXXXXXXXXXXXXXXXXXXXXXX \n");
   }
}

// ----------------------------------------------------------------------------
// lookup() - lookup query in cache
// ----------------------------------------------------------------------------
int DNSDistNamedCache::lookup(const std::string& strQuery, std::string& strData)
{
    int iLoc = nc->getCache(strQuery, strData);
    switch(iLoc)
      {
       case CACHE_HIT::HIT_CACHE:
            cache_hits++;
            break;
       case CACHE_HIT::HIT_CDB:
            cdb_hits++;
            break;
       case CACHE_HIT::HIT_NONE:
            cache_miss++;
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
    return(cache_hits);
}

// ----------------------------------------------------------------------------
// getCdbHits() - get current number of cdb hits
// ----------------------------------------------------------------------------
uint64_t DNSDistNamedCache::getCdbHits()
{
    return(cdb_hits);
}

// ----------------------------------------------------------------------------
// getCacheMiss() - get current number of cache misses
// ----------------------------------------------------------------------------
uint64_t DNSDistNamedCache::getCacheMiss()
{
    return(cache_miss);
}

// ----------------------------------------------------------------------------
// isFileOpen() - return true if file open
// ----------------------------------------------------------------------------
bool DNSDistNamedCache::isFileOpen()
{
    return(bOpened);
}

// ----------------------------------------------------------------------------
