#include "config.h"

#include "dnsdist-nc-lrucache2.hh"

#ifdef HAVE_NAMEDCACHE

// ----------------------------------------------------------------------------
// This LRU cache is not thread safe, as it doesn't have to be
// as all calls are from LUA code.
// Comment from: https://dnsdist.org/advanced/tuning.html
//      "Lua processing in dnsdist is serialized by an unique lock for all threads."
// ----------------------------------------------------------------------------
Node* DoublyLinkedList::add_page_to_head(std::string key, std::string value)
{
  Node *page = new Node(key, value);
  if(!front && !rear) {
    front = rear = page;
  } else {
      page->next = front;
      front->prev = page;
      front = page;
    }
  return page;
}

void DoublyLinkedList::move_page_to_head(Node *page)
{
  if(page==front) {
    return;
  }
  if(page == rear) {
    rear = rear->prev;
    rear->next = NULL;
  } else {
      page->prev->next = page->next;
      page->next->prev = page->prev;
    }

  page->next = front;
  page->prev = NULL;
  front->prev = page;
  front = page;
}

void DoublyLinkedList::remove_rear_page()
{
  if(isEmpty()) {
    return;
  }
  if(front == rear) {
    delete rear;
    front = rear = NULL;
  } else {
      Node *temp = rear;
      rear = rear->prev;
      rear->next = NULL;
      delete temp;
    }
}

Node* DoublyLinkedList::get_rear_page()
{
  return rear;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
LRUCache2::LRUCache2()
{
}

bool LRUCache2::setCacheMode(int iMode)
{
  iCacheMode = iMode;
  return(true);
}

bool LRUCache2::init(int capacity, int iCacheMode)
{
  setCacheMode(iCacheMode);
  this->capacity = capacity;
  size = 0;
  pageList = new DoublyLinkedList();
  pageMap = std::map<std::string, Node*>();
  return(true);
}

bool LRUCache2::get(std::string key, std::string &val)
{
  if(pageMap.find(key)==pageMap.end()) {
    val = "";
    return false;
  }
  val = pageMap[key]->value;
  pageList->move_page_to_head(pageMap[key]);    // move the page to front
  return true;
}

void LRUCache2::put(std::string key, std::string value)
{
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

int LRUCache2::getSize()
{
  return(capacity);
}

int LRUCache2::getEntries()               // not used at present
{
  return(size);
}

int LRUCache2::getErrNum()
{
  return(cdbFH.getErrNum());            // get error number from cdbIO
}

std::string LRUCache2::getErrMsg()
{
  return(cdbFH.getErrMsg());            // get error message from cdbIO
}

LRUCache2::~LRUCache2()
{
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
bool LRUCache2::open(std::string strCdbName)
{
bool bStatus = false;

  bStatus = cdbFH.open(strCdbName); 
  return(bStatus);
}

bool LRUCache2::close()
{
bool bStatus = false;

  bStatus = cdbFH.close();
  return(bStatus);
}

// ----------------------------------------------------------------------------
// getCDBCache() - read from cache / cdb - strValue cleared if not written to
// ----------------------------------------------------------------------------
int LRUCache2::getCache(const std::string strKey, std::string &strValue)
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
