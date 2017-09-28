
#include "dnsdist-nc-nocache.hh"

#ifdef HAVE_NAMEDCACHE

NoCache::NoCache() {
}


NoCache::~NoCache() {
}

bool NoCache::close() {

    return(true);
}

bool NoCache::open(std::string strFileName)
{

  return(true);
}


int NoCache::getErrNum()
{
  return(0);
}

std::string NoCache::getErrMsg()
{
  return("");
}

bool NoCache::setCacheMode(int iMode)
{
  (void) iMode;         // not used
  return(true);
}

bool NoCache::init(int iEntries, int iCacheMode)
{
  setCacheMode(iCacheMode);
  (void) iEntries;        // not used
  return(true);
}

int NoCache::getSize()
{
  return(0);
}

int NoCache::getEntries()
{
  return(0);
}

// ----------------------------------------------------------------------------
// getCDBCache() - read from cache / cdb - strValue cleared if not written to
// ----------------------------------------------------------------------------
int NoCache::getCache(const std::string strKey, std::string &strValue)
{
int iStatus = CACHE_HIT::HIT_NONE;

  return(iStatus);
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
CdbNoCache::CdbNoCache()
{
}

CdbNoCache::~CdbNoCache()
{
}

bool CdbNoCache::close()
{

  bool bStatus = cdbFH.close();

  return(bStatus);
}

bool CdbNoCache::open(std::string strFileName)
{
bool bStatus = false;

  bStatus = cdbFH.open(strFileName);

  return(bStatus);
}

int CdbNoCache::getErrNum()
{
  return(cdbFH.getErrNum());            // get error number from cdbIO

}

std::string CdbNoCache::getErrMsg()
{
  return(cdbFH.getErrMsg());            // get error message from cdbIO

}

bool CdbNoCache::setCacheMode(int iMode)
{
  (void) iMode;         // not used
  return(true);
}

bool CdbNoCache::init(int iEntries, int iCacheMode)
{
  setCacheMode(iCacheMode);
  (void) iEntries;        // not used
  return(true);
}

int CdbNoCache::getSize()
{
  return(0);
}

int CdbNoCache::getEntries()
{
  return(0);
}

// ----------------------------------------------------------------------------
// getCDBCache() - read from cache / cdb - strValue cleared if not written to
// ----------------------------------------------------------------------------
int CdbNoCache::getCache(const std::string strKey, std::string &strValue)
{
int iStatus = CACHE_HIT::HIT_NONE;

  bool bGotCache = cdbFH.get(strKey, strValue);      // read from cache
  if(bGotCache == false) {
    iStatus = CACHE_HIT::HIT_NONE;
  } else {
      iStatus = CACHE_HIT::HIT_CDB;
    }

  return(iStatus);
}

#endif
