#include "dnsdist-nc-cdbio.hh"

// ----------------------------------------------------------------------------
// openCDB()
// see:  http://cr.yp.to/cdb/reading.html
// ----------------------------------------------------------------------------
cdbIO::cdbIO() {

    fd = -1;
}

// ----------------------------------------------------------------------------
cdbIO::~cdbIO() {

    close();
}

// ----------------------------------------------------------------------------
bool cdbIO::open(std::string strCdbName)  {
bool bStatus = false;

	fd = ::open(strCdbName.c_str(), O_RDONLY);                // open the CDB file
	if(fd != -1)
	  {
	   cdb_init(&cdbX, fd);                                 // initialize internal structure
	   bStatus = true;
	  }

    return(bStatus);
}

// ----------------------------------------------------------------------------
bool cdbIO::close()  {
bool bStatus = false;

    if(fd != -1)
      {
       cdb_free(&cdbX);                                     // free internal structure
       ::close(fd);
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
bool cdbIO::get(std::string strKey, std::string &strValue) {
bool bStatus = false;
void *ptrVal;
uint32_t vpos;
unsigned int vlen;

    strValue.clear();

    if(fd != -1)
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
