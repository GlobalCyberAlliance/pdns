// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#include "dnsdist-nc-nocache.hh"

// ----------------------------------------------------------------------------
NoCache::NoCache() {
}


// ----------------------------------------------------------------------------
NoCache::~NoCache() {
}

// ----------------------------------------------------------------------------
bool NoCache::close() {

    bool bStatus = cdbFH.close();

    return(bStatus);
}
// ----------------------------------------------------------------------------
bool NoCache::open(std::string strFileName)
{
bool bStatus = false;

    bStatus = cdbFH.open(strFileName);

    return(bStatus);
}



// ----------------------------------------------------------------------------
std::string NoCache::getErrMsg()
{
    return(strErrMsg);
}

// ----------------------------------------------------------------------------
bool NoCache::setCacheMode(int iMode) {
      (void) iMode;         // not used
      return(true);
    }

// ----------------------------------------------------------------------------
bool NoCache::init(int iEntries, int iCacheMode)
{
    setCacheMode(iCacheMode);
    (void) iEntries;        // not used
    return(true);
}

// ----------------------------------------------------------------------------
int NoCache::getSize()
{
    return(0);
}

// ----------------------------------------------------------------------------
int NoCache::getEntries()
{
    return(0);
}

// ----------------------------------------------------------------------------
// getCDBCache() - read from cache / cdb - strValue cleared if not written to
// ----------------------------------------------------------------------------
int NoCache::getCache(const std::string strKey, std::string &strValue) {
int iStatus = CACHE_HIT::HIT_NONE;

    bool bGotCache = cdbFH.get(strKey, strValue);      // read from cache
    if(bGotCache == false)
      {
       iStatus = CACHE_HIT::HIT_NONE;
      }
    else
      {
       iStatus = CACHE_HIT::HIT_CDB;
      }


    return(iStatus);
}


// ----------------------------------------------------------------------------
