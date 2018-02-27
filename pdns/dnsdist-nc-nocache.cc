
#include "dnsdist-nc-nocache.hh"

#ifdef HAVE_NAMEDCACHE

// GCA - empty named cache place holder
NoCache::NoCache() {
  iDebug = 0;
}


NoCache::~NoCache() {
}

void NoCache::setDebug(int debug) {
  iDebug = debug;
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
  iCacheMode = iMode;
  return(true);
}

bool NoCache::init(int iEntries, int iCacheMode)
{
  setCacheMode(iCacheMode);
  (void) iEntries;
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

int NoCache::getCache(const std::string strKey, std::string &strValue)
{
int iStatus = CACHE_HIT::HIT_NONE;

  switch(iCacheMode) {
  case CACHE_MODE::MODE_TEST:
    strValue = "Test";
    iStatus = CACHE_HIT::HIT_CACHE;
    break;
  default:
    break;
  }

  return(iStatus);
}



CdbNoCache::CdbNoCache()
{
  iDebug = 0;
}

CdbNoCache::~CdbNoCache()
{
}

void CdbNoCache::setDebug(int debug) {
  iDebug = debug;
  cdbFH.setDebug(iDebug);
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
  (void) iMode;
  return(true);
}

bool CdbNoCache::init(int iEntries, int iCacheMode)
{
  setCacheMode(iCacheMode);
  (void) iEntries;
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

//  read from cache / cdb - strValue cleared if not written to
int CdbNoCache::getCache(const std::string strKey, std::string &strValue)
{
int iStatus = CACHE_HIT::HIT_NONE;

  bool bGotCache = cdbFH.get(strKey, strValue);
  if(bGotCache == false) {
    iStatus = CACHE_HIT::HIT_NONE;
  } else {
      iStatus = CACHE_HIT::HIT_CDB;
    }

  return(iStatus);
}

#endif
