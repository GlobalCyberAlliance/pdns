#ifndef CDBIO_H
#define CDBIO_H

#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <cdb.h>

class cdbIO {

public:

cdbIO();
~cdbIO();
bool open(std::string strCdbName);
bool close();
bool get(std::string strKey, std::string &strValue);

private:
  int fd;                               // cdb file descriptor
  struct cdb cdbX;                      // cdb file info
};


#endif // CDBIO_H
