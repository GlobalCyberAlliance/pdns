// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#include <iostream>
#include <map>

using namespace std;


#include "dnsdist-lrucache.hh"

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
CdbMapCache::CdbMapCache() {
    iEntriesRead = 0;
    mapKeyData.clear();
}


// ----------------------------------------------------------------------------
CdbMapCache::~CdbMapCache() {
    iEntriesRead = 0;
    mapKeyData.clear();
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

// ----------------------------------------------------------------------------
int CdbMapCache::getNum(int fd, uint32_t &u32Num)
{
int iStatus = 0;
char buf[5];

    ssize_t bytes_read = read(fd, buf, 4);
    if(bytes_read != 4)
      {
       iStatus = -1;
      }
    else
      {
       uint32_unpack(buf, &u32Num);
      }
    return(iStatus);
}

// ----------------------------------------------------------------------------
int CdbMapCache::getText(int fd, unsigned int uBytes, std::string &strData)
{
int iStatus = 0;
char buf[512];

    strData.clear();
    if(uBytes > 512)
      {
       iStatus = -1;
      }
    else
      {
       ssize_t bytes_read = read(fd, buf, uBytes);
       if(bytes_read != uBytes)
         {
          iStatus = -2;
         }
       else
         {
          strData.append((const char *) buf, uBytes);
         }
      }

    return(iStatus);
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
int fd = -1;
//uint32_t u32Num;
uint32_t u32HashTableStart = 0;                              // offset of hash table
uint32_t u32HashOffset;
uint32_t u32HashEntries;
uint32_t u32KeyLen;
uint32_t u32DataLen;
//uint32_t u32TotalLen = 0;
std::string strKey;
std::string strData;

    iEntriesRead = 0;
    mapKeyData.clear();
	fd = open(strCdbName.c_str(), O_RDONLY); 				// open the CDB file
	if(fd < 0)
	  {
	   iStatus = -1;
	  }


    if(iStatus == 0)
      {
       for(int ii=0; ii < 256; ii++)
          {                                                 // read toc section
           if(getNum(fd, u32HashOffset) != 0)
             {
              iStatus = -3;
              break;
             }
           else
             {
              if(ii == 0)
                {                                           // mark start of hash tables
                 u32HashTableStart = u32HashOffset;
                }
             }
           if(getNum(fd, u32HashEntries) != 0)
             {
              iStatus = -4;
              break;
             }
           if(iStatus == 0)
             {
              if(iDebug > 0)
                {
                 printf("\t%3.3d   HashOff: %u   HashEntires: %u \n", ii, u32HashOffset, u32HashEntries);
                }
             }
          }
      }

    if(iStatus == 0)
      {
       while(iStatus == 0)
          {                                                 // read data section
           off_t ofLoc = lseek(fd, 0, SEEK_CUR);
           if(ofLoc == u32HashTableStart)
             {                                              // end of data section, hash table follows
              break;
             }
           if(getNum(fd, u32KeyLen) != 0)
             {
              iStatus = -4;
             }
           else
             {
              if(getNum(fd, u32DataLen) != 0)
                {
                 iStatus = -5;
                }
             }

          if(iStatus == 0)
            {
             if(getText(fd, u32KeyLen, strKey) != 0)
               {
                iStatus = -6;
               }
             else
               {
                if(getText(fd, u32DataLen, strData) != 0)
                  {
                   iStatus = -7;
                  }
               }
            }

          if(iDebug > 0)
            {
             if(iStatus == 0)
               {
                printf("\tEntry......: %d \n", iEntriesRead);
                printf("\tKey length.: %u \n", u32KeyLen);
                printf("\tData length: %u \n", u32DataLen);
                printf("\tKey........: %s \n", strKey.c_str());
                printf("\tData.......: %s \n", strData.c_str());
               }
            }

#ifdef TRASH
          struct KeyData kdTemp;
          kdTemp.strKey  = strKey;
          kdTemp.strData = strData;
          vecKeyData.push_back(kdTemp);
#endif
          mapKeyData.insert ( std::pair<string, string>(strKey, strData) );
          iEntriesRead++;
         }
      }


    if(iDebug > 0)
      {
       off_t ofLoc = lseek(fd, 0, SEEK_CUR);
       printf("\tCurrent loc: %lu \n", ofLoc);
      }

    if(fd != -1)
      {
       close(fd);
      }


    return(iStatus);
}

// ----------------------------------------------------------------------------
int CdbMapCache::getCacheSize()
{
    return(mapKeyData.size());
}

// ----------------------------------------------------------------------------
int CdbMapCache::getCdbEntries()
{
    return(iEntriesRead);
}

// ----------------------------------------------------------------------------
bool CdbMapCache::get(std::string strKey, std::string &strData) {
bool bStat = false;

   auto it = mapKeyData.find(strKey);
   if (it != mapKeyData.end())
     {
      strData = it->second;
      bStat = true;
     }
   else
     {
      strData = "";
      bStat = false;
     }

   return(bStat);


}

// ----------------------------------------------------------------------------
// getCDBCache() - read from cache / cdb - strValue cleared if not written to
// ----------------------------------------------------------------------------
int CdbMapCache::getCache(const std::string strKey, std::string &strValue) {
int iStatus = LOC::NONE;

    strValue.clear();
    bool bGotCache = get(strKey, strValue);      // read from cache
    if(bGotCache == false)
      {
       iStatus = LOC::NONE;
      }
    else
      {
       iStatus = LOC::CACHE;
      }


    return(iStatus);
}


// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
LRUCache::LRUCache() {
}

// ----------------------------------------------------------------------------
bool LRUCache::init(int capacity) {
      fd = -1;
      this->capacity = capacity;
      size = 0;
      pageList = new DoublyLinkedList();
      pageMap = map<std::string, Node*>();
      return(true);
    }

// ----------------------------------------------------------------------------
    bool LRUCache::get(std::string key, std::string &val) {
        if(pageMap.find(key)==pageMap.end()) {
          val = "";
          return false;
        }
        val = pageMap[key]->value;

        // move the page to front
        pageList->move_page_to_head(pageMap[key]);
        return true;
    }

// ----------------------------------------------------------------------------
void LRUCache::put(std::string key, std::string value) {
      if(pageMap.find(key)!=pageMap.end()) {
          // if key already present, update value and move page to head
          pageMap[key]->value = value;
          pageList->move_page_to_head(pageMap[key]);
          return;
      }

        if(size == capacity) {
          // remove rear page
          std::string k = pageList->get_rear_page()->key;
          pageMap.erase(k);
          pageList->remove_rear_page();
          size--;
        }

        // add new page to head to Queue
        Node *page = pageList->add_page_to_head(key, value);
        size++;
        pageMap[key] = page;
    }

// ----------------------------------------------------------------------------
int LRUCache::getCacheSize()
{
    return(size);
}

// ----------------------------------------------------------------------------
LRUCache::~LRUCache() {
      map<std::string, Node*>::iterator i1;
      for(i1=pageMap.begin();i1!=pageMap.end();i1++) {
          delete i1->second;
      }
      delete pageList;
      closeCDB();
    }

// ----------------------------------------------------------------------------
// openCDB()
// see:  http://cr.yp.to/cdb/reading.html
// ----------------------------------------------------------------------------
bool LRUCache::openCDB(std::string strCdbName)  {
bool bStatus = false;

	fd = open(strCdbName.c_str(), O_RDONLY); 				// open the CDB file
	if(fd >= 0)
	  {
	   cdb_init(&cdbX, fd);                                 // initialize internal structure
	   bStatus = true;
	  }

    return(bStatus);
}

// ----------------------------------------------------------------------------
bool LRUCache::closeCDB()  {
bool bStatus = false;

    if(fd != -1)
      {
       cdb_free(&cdbX);                                     // free internal structure
       close(fd);
       fd = -1;
       bStatus = true;
      }

    return(bStatus);
}

// ----------------------------------------------------------------------------
// getCDB() - lookup key in cdb and set value if found
//            assume that there is only one entry for a key
//            return true if found
// ----------------------------------------------------------------------------
bool LRUCache::getCDB(std::string strKey, std::string &strValue) {
bool bStatus = false;
void *ptrVal;
uint32_t vpos;
unsigned int vlen;

    strValue.clear();

    if(fd >= 0)
	  {
       if (cdb_find(&cdbX, strKey.c_str(), strKey.length()) > 0)
         {                                                   // if search successeful
          vpos = cdb_datapos(&cdbX);                         // position of data in a file
          vlen = cdb_datalen(&cdbX);                         // length of data
          ptrVal = malloc(vlen);                             // allocate memory
          cdb_read(&cdbX, ptrVal, vlen, vpos);               // read the value into buffer

  	      strValue.append((const char *) ptrVal, vlen);      // handle the value here

          free(ptrVal);                                      // free up memory
          bStatus = true;
         }
      }

    return(bStatus);
}

// ----------------------------------------------------------------------------
// getCDBCache() - read from cache / cdb - strValue cleared if not written to
// ----------------------------------------------------------------------------
int LRUCache::getCache(const std::string strKey, std::string &strValue) {
int iStatus = LOC::NONE;
bool bGotCache;
bool bGotCDB;

    strValue.clear();
    bGotCache = get(strKey, strValue);      // read from cache
    if(bGotCache == false)
      {
       bGotCDB = getCDB(strKey, strValue);  // read from CDB
       if(bGotCDB == true)
         {
          put(strKey, strValue);            // store in cache
          iStatus = LOC::CDB;
         }
       else
         {
          put(strKey, "");                  // put empty value in cache
          iStatus = LOC::NONE;
         }
      }
    else
      {
       iStatus = LOC::CACHE;
      }


    return(iStatus);
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

NamedCache::NamedCache()
{
}

NamedCache::~NamedCache()
{
}

bool NamedCache::setSize(int iEntries)
{
bool bStatus = true;

    return(bStatus);
}

int  NamedCache::getSize()
{
int iSize = 0;

    return(iSize);
}

int  NamedCache::getEntries()
{
int iEntries = 0;

    return(iEntries);
}

bool NamedCache::setMode(int iMode)
{
bool bStatus = true;

    return(bStatus);
}

std::string NamedCache::errMsg()
{
std::string strErrMsg = "";

    return(strErrMsg);
}

bool NamedCache::open(std::string strFileName)
{
bool bStatus = true;

    return(bStatus);
}

bool NamedCache::close()
{
bool bStatus = true;

    return(bStatus);
}

bool NamedCache::get(std::string strKey, std::string &strValue)
{
bool bStatus = true;

    strValue.clear();
    return(bStatus);

}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
