#ifndef LRUCACHE_H
#define LRUCACHE_H

#include <fcntl.h>
#include <unistd.h>
#include <cdb.h>
#include <map>

#include "dnsdist-nc-cdbio.hh"
#include "dnsdist-nc-namedcache.hh"


// ----------------------------------------------------------------------------
class Node {
  public:
  std::string key, value;
  Node *prev, *next;
  Node(std::string k, std::string v): key(k), value(v), prev(NULL), next(NULL) {}
};

// ----------------------------------------------------------------------------
class DoublyLinkedList {
private:
    Node *front, *rear;
      bool isEmpty() {return rear == NULL;}

public:
  DoublyLinkedList(): front(NULL), rear(NULL) {}
  Node* add_page_to_head(std::string key, std::string value);
  void move_page_to_head(Node *page);
  void remove_rear_page();
  Node* get_rear_page();
};

// ----------------------------------------------------------------------------
class LRUCache : public NamedCache  {

public:

  LRUCache();
  ~LRUCache();
  bool setCacheMode(int iMode);
  bool init(int capacity, int iCacheMode);
  int  getSize();
  std::string getErrMsg(void);
  bool open(std::string strFileName);
  bool close();
  int  getCache(const std::string strKey, std::string &strValue);
  int  getEntries();


private:

  int capacity, size;
  int iCacheMode;                       // CACHE::NONE, CACHE::RPZ, CACHE::ALL
  DoublyLinkedList *pageList;
  std::map<std::string, Node*> pageMap;
//  int fd;                               // cdb file descriptor
//  struct cdb cdbX;                      // cdb file info
  cdbIO cdbFH;
  std::string strErrMsg;

void put(std::string key, std::string value);
bool get(std::string key, std::string &val);
//bool getCDB(std::string strKey, std::string &strValue);

};

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#endif // LRUCACHE_H
