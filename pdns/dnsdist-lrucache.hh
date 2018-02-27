#ifndef LRUCACHE_H
#define LRUCACHE_H

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <cdb.h>
#include <map>

///using namespace std;

enum LOC {NONE, CDB, CACHE};


// ----------------------------------------------------------------------------
class CdbMapCache {

public:
   CdbMapCache();
   ~CdbMapCache();
   int  loadCdbMap(std::string strCdbName, int iDebug=0);
   int  getCacheSize();
   int  getCdbEntries();
   int  getCache(const std::string strKey, std::string &strValue);
private:
   int  iEntriesRead;
   std::map<string, string> mapKeyData;
   void uint32_unpack(char s[4],uint32_t *u);
   int  getNum(int fd, uint32_t &u32Num);
   int  getText(int fd, unsigned int uBytes, std::string &strData);
   bool get(std::string key, std::string &strData);
};


// ----------------------------------------------------------------------------
class Node {
  public:
  std::string key, value;
  Node *prev, *next;
  Node(std::string k, std::string v): key(k), value(v), prev(NULL), next(NULL) {}
};

// ----------------------------------------------------------------------------
class DoublyLinkedList {
  Node *front, *rear;

  bool isEmpty() {
      return rear == NULL;
  }

  public:
  DoublyLinkedList(): front(NULL), rear(NULL) {}

  Node* add_page_to_head(std::string key, std::string value) {
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

  void move_page_to_head(Node *page) {
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

  void remove_rear_page() {
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
  Node* get_rear_page() {
      return rear;
  }

};



class LRUCache {

public:

  LRUCache();
  ~LRUCache();
  bool init(int capacity);
  int  getCacheSize();
  bool openCDB(std::string strFileName);
  bool closeCDB();
  int  getCache(const std::string strKey, std::string &strValue);


private:

  int capacity, size;
  DoublyLinkedList *pageList;
  map<std::string, Node*> pageMap;
  int fd;                               // cdb file descriptor
  struct cdb cdbX;                      // cdb file info

void put(std::string key, std::string value);
bool get(std::string key, std::string &val);
bool getCDB(std::string strKey, std::string &strValue);

};


class NamedCache {

public:

  NamedCache();
  ~NamedCache();
  bool setSize(int iEntries);
  int  getSize();
  int  getEntries();
  bool setMode(int iMode);
  std::string errMsg();
  bool open(std::string strFileName);
  bool close();
  bool get(std::string strKey, std::string &strValue);

};

#endif // LRUCACHE_H
