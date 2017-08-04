// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#include <iostream>
#include <map>

using namespace std;


#include "dnsdist-lrucache.hh"


// ----------------------------------------------------------------------------
LRUCache2::LRUCache2() {
}

// ----------------------------------------------------------------------------
bool LRUCache2::init(int capacity) {
      fd = -1;
      this->capacity = capacity;
      size = 0;
      pageList = new DoublyLinkedList();
      pageMap = map<std::string, Node*>();
      return(true);
    }

// ----------------------------------------------------------------------------
    bool LRUCache2::get(std::string key, std::string &val) {
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
void LRUCache2::put(std::string key, std::string value) {
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
int LRUCache2::getCacheSize()
{
    return(size);
}

// ----------------------------------------------------------------------------
LRUCache2::~LRUCache2() {
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
bool LRUCache2::openCDB(std::string strCdbName)  {
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
bool LRUCache2::closeCDB()  {
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
bool LRUCache2::getCDB(std::string strKey, std::string &strValue) {
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
int LRUCache2::getCDBCache(const std::string strKey, std::string &strValue) {
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
