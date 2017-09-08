// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------


#include "dnsdist-nc-lrucache.hh"

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
  Node* DoublyLinkedList::add_page_to_head(std::string key, std::string value) {
      Node *page = new Node(key, value);
      if(!front && !rear) {
          front = rear = page;
      }
      else {
          page->next = front;
          front->prev = page;
          front = page;
      }
      return page;
  }

  void DoublyLinkedList::move_page_to_head(Node *page) {
      if(page==front) {
          return;
      }
      if(page == rear) {
          rear = rear->prev;
          rear->next = NULL;
      }
      else {
          page->prev->next = page->next;
          page->next->prev = page->prev;
      }

      page->next = front;
      page->prev = NULL;
      front->prev = page;
      front = page;
  }

  void DoublyLinkedList::remove_rear_page() {
      if(isEmpty()) {
          return;
      }
      if(front == rear) {
          delete rear;
          front = rear = NULL;
      }
      else {
          Node *temp = rear;
          rear = rear->prev;
          rear->next = NULL;
          delete temp;
      }
  }
  Node* DoublyLinkedList::get_rear_page() {
      return rear;
  }

// ----------------------------------------------------------------------------
LRUCache::LRUCache() {
}

// ----------------------------------------------------------------------------
bool LRUCache::setCacheMode(int iMode) {
      iCacheMode = iMode;
      return(true);
    }

// ----------------------------------------------------------------------------
bool LRUCache::init(int capacity, int iCacheMode) {
//      fd = -1;
      setCacheMode(iCacheMode);
      this->capacity = capacity;
      size = 0;
      pageList = new DoublyLinkedList();
      pageMap = std::map<std::string, Node*>();
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
int LRUCache::getSize()
{
    return(capacity);
}

// ----------------------------------------------------------------------------
int LRUCache::getEntries()               // not used at present
{
    return(size);
}
// ----------------------------------------------------------------------------
std::string LRUCache::getErrMsg()
{
    return(strErrMsg);
}

// ----------------------------------------------------------------------------
LRUCache::~LRUCache() {
      std::map<std::string, Node*>::iterator i1;
      for(i1=pageMap.begin();i1!=pageMap.end();i1++) {
          delete i1->second;
      }
      delete pageList;
      close();
    }

// ----------------------------------------------------------------------------
// openCDB()
// see:  http://cr.yp.to/cdb/reading.html
// ----------------------------------------------------------------------------
bool LRUCache::open(std::string strCdbName)  {
bool bStatus = false;

    bStatus = cdbFH.open(strCdbName);
    return(bStatus);
}

// ----------------------------------------------------------------------------
bool LRUCache::close()  {
bool bStatus = false;

    bStatus = cdbFH.close();
    return(bStatus);
}

// ----------------------------------------------------------------------------
// getCDBCache() - read from cache / cdb - strValue cleared if not written to
// ----------------------------------------------------------------------------
int LRUCache::getCache(const std::string strKey, std::string &strValue) {
int iStatus = CACHE_HIT::HIT_NONE;
bool bGotCache;
bool bGotCDB;

    bGotCache = get(strKey, strValue);      // read from cache
    if(bGotCache == false)
      {
       bGotCDB = cdbFH.get(strKey, strValue);  // read from CDB
       if(bGotCDB == true)
         {
          if(iCacheMode >= CACHE_MODE::MODE_RPZ)
            {
             put(strKey, strValue);            // store in cache
            }
          if(strValue.empty()) {
            iStatus = CACHE_HIT::HIT_CDB_NO_DATA;
            } else {
              iStatus = CACHE_HIT::HIT_CDB;
              }
         }
       else
         {
          if(iCacheMode == CACHE_MODE::MODE_ALL)
            {
             put(strKey, "");              // put empty value in cache
            }
          iStatus = CACHE_HIT::HIT_NONE;
         }
      }
    else
      {
       if(strValue.empty()) {
         iStatus = CACHE_HIT::HIT_CACHE_NO_DATA;
         } else {
         iStatus = CACHE_HIT::HIT_CACHE;
         }
      }


    return(iStatus);
}

