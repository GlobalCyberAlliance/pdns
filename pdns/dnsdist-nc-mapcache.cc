
#include "config.h"

#include "dnsdist-nc-mapcache.hh"

#ifdef HAVE_NAMEDCACHE

CdbMapCache::CdbMapCache()
{
  iErrNum = 0;
  iEntriesRead = 0;
  mapKeyData.clear();
}

CdbMapCache::~CdbMapCache()
{
  iEntriesRead = 0;
  mapKeyData.clear();
}

bool CdbMapCache::close()
{
  return(true);
}

bool CdbMapCache::open(std::string strFileName)
{
std::string strErrNo;

  int iStatus = loadCdbMap(strFileName);
  if(iStatus >= 0) {
    strErrMsg = "";
    return(true);
  }
  iErrNum = errno;              // only come from loadCdbMap
  if(errno != 0) {
    iErrNum = errno;
    strErrNo = strerror(errno);
  }

  strErrMsg = "CdbMapCache::open() - Error: " + std::to_string(iStatus) + "  IOErr: " + std::to_string(iErrNum) + "  IOMsg: " + strErrNo;
  return(false);
}

// ----------------------------------------------------------------------------
// from uint32_unpack
// ----------------------------------------------------------------------------
void CdbMapCache::uint32_unpack(char s[4],uint32_t *u)
{
  uint32_t result;

  result = (unsigned char) s[3];
  result <<= 8;
  result += (unsigned char) s[2];
  result <<= 8;
  result += (unsigned char) s[1];
  result <<= 8;
  result += (unsigned char) s[0];

  *u = result;
}

int CdbMapCache::getNum(FILE *fio, uint32_t &u32Num)
{
char buf[5];

  ssize_t bytes_read = fread(buf, 1, 4, fio);
  if(bytes_read != 4) {
    return(-1);
  }
  uint32_unpack(buf, &u32Num);
  return(0);
}

int CdbMapCache::getText(FILE *fio, unsigned int uBytes, std::string &strData)
{
char buf[512];              // limiting length of data....

  strData.clear();
  if(uBytes > 512) {
    return(-1);
  }
  ssize_t bytes_read = fread(buf, 1, uBytes, fio);
  if(bytes_read != uBytes) {
     return(-2);
    }
  strData.append((const char *) buf, uBytes);
  return(0);
}

// ----------------------------------------------------------------------------
// loadCdbMap() - load entire cdb into map
//
// From: https://manpages.debian.org/jessie/tinycdb/cdb.5.en.html
// CDB parts: toc (table of contents), data and index (hash tables).
//
// Toc has fixed length of 2048 bytes.
// Toc contains 256 pointers to hash tables inside index sections.
//
// Every pointer consists of position of a hash table in bytes from the
// beginning of a file, and a size of a hash table in entries, both are
// 4-bytes (32 bits) unsigned integers in little-endian form.
// Hash table length may have zero length, indicating hash table is empty.
//
// Right after toc section, data section follows without any alingment.
// Toc consists of series of records, each is a key length,
// value (data) length, key and value.
// The key and value length are 4-byte unsigned integers.
// Each record follows previous without any special alignment.
//
// Right after data section Index (hash tables) section follows.
// Every hash table is a sequence of records each holds two numbers:
// the key's hash value and record position inside data section.
// Record position is bytes from the beginning of a file to first byte
// of key length starting data record.
//
// ----------------------------------------------------------------------------
int CdbMapCache::loadCdbMap(std::string strCdbName, int iDebug)
{
int iStatus = 0;
FILE *fio = NULL;
uint32_t u32HashTableStart = 0;                              // offset of hash table
uint32_t u32HashOffset;
uint32_t u32HashEntries;
uint32_t u32KeyLen;
uint32_t u32DataLen;
std::string strKey;
std::string strData;

  iEntriesRead = 0;
  mapKeyData.clear();

  fio = fopen(strCdbName.c_str(), "rb");                    // open the CDB file
  if(fio == NULL) {
    iStatus = -1;
  }

  if(iStatus == 0) {
    for(int ii=0; ii < 256; ii++)  {                        // read toc section
       if(getNum(fio, u32HashOffset) != 0) {
         iStatus = -3;
          break;
       } else {
           if(ii == 0) {                                    // mark start of hash tables
             u32HashTableStart = u32HashOffset;
           }
         }
      if(getNum(fio, u32HashEntries) != 0) {
        iStatus = -4;
        break;
      }
      if(iStatus == 0) {
        if(iDebug > 0) {
          printf("\t%3.3d   HashOff: %u   HashEntires: %u \n", ii, u32HashOffset, u32HashEntries);
        }
      }
    }
  }

  if(iStatus == 0) {
    while(iStatus == 0) {                                   // read data section
      off_t ofLoc = ftell(fio);
      if(ofLoc == u32HashTableStart) {                      // end of data section, hash table follows
        break;
      }
     if(getNum(fio, u32KeyLen) != 0) {
       iStatus = -4;
     } else {
         if(getNum(fio, u32DataLen) != 0) {
           iStatus = -5;
         }
       }

     if(iStatus == 0) {
       if(getText(fio, u32KeyLen, strKey) != 0) {
         iStatus = -6;
       } else {
           if(getText(fio, u32DataLen, strData) != 0) {
             iStatus = -7;
           }
         }
     }

     if(iDebug > 0) {
       if(iStatus == 0) {
         printf("\tEntry......: %d \n", iEntriesRead);
         printf("\tKey length.: %u \n", u32KeyLen);
         printf("\tData length: %u \n", u32DataLen);
         printf("\tKey........: %s \n", strKey.c_str());
         printf("\tData.......: %s \n", strData.c_str());
       }
     }


// ----------------------------------------------------------------------------
// GCA - Seth - 10/20/2017 Experimental Debugging....... SLOW LOADING FROM DISK
//              This takes about 11 secs to load 800,000 entries
//              with this delay in the code.
//              Used to debug named cache reloading
// ----------------------------------------------------------------------------

#ifdef LOAD_CDB_MAP
     long int ii;
     int jj = 0;
     for(ii=0; ii < 30; ii++) {
        long int kk = 0;
        for(kk=0; kk < 1; kk++) {
           long int ll = 0;
            for(ll=0; ll < 1; ll++) {
               jj+=300;
               jj/= 7;
               jj*=300;
               jj/= 5;
               long int mm = 0;
               for(mm = 0; mm < 2; mm++)  {
                  auto xx = mapKeyData.find("xxx");
                  if (xx == mapKeyData.end()) {
                    jj += 1;
                  }
               }
            }
        }
     }
#endif

// ----------------------------------------------------------------------------

     mapKeyData.insert ( std::pair<std::string, std::string>(strKey, strData) );
     iEntriesRead++;
    }
  }

  if(iDebug > 0) {
     off_t ofLoc = ftell(fio);
     printf("\tCurrent loc: %lu \n", ofLoc);
  }

  if(fio != NULL) {
    fclose(fio);
    fio = NULL;
  }


  return(iStatus);
}

int CdbMapCache::getErrNum()
{
  return(iErrNum);
}

std::string CdbMapCache::getErrMsg()
{
  return(strErrMsg);
}

bool CdbMapCache::setCacheMode(int iMode)
{
  iCacheMode = iMode;
  return(true);
}

bool CdbMapCache::init(int iEntries, int iCacheMode)      // not used at present
{
  setCacheMode(iCacheMode);
  iEntries = 0;           // not used
  return(true);
}

int CdbMapCache::getSize()
{
  return(mapKeyData.size());
}

int CdbMapCache::getEntries()
{
  return(iEntriesRead);
}

bool CdbMapCache::get(std::string strKey, std::string &strData)
{

  auto it = mapKeyData.find(strKey);
  if(it != mapKeyData.end()) {
    strData = it->second;
    return(true);
  }
  strData = "";
  return(false);
}

// ----------------------------------------------------------------------------
// getCDBCache() - read from cache / cdb - strValue cleared if not written to
// ----------------------------------------------------------------------------
int CdbMapCache::getCache(const std::string strKey, std::string &strValue)
{

  strValue.clear();
  bool bGotCache = get(strKey, strValue);      // read from cache
  if(bGotCache == false) {
    return(CACHE_HIT::HIT_NONE);
  }
  return(CACHE_HIT::HIT_CACHE);
}


#endif
