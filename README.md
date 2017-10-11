PowerDNS is copyright © 2002-2016 by PowerDNS.COM BV and lots of
contributors, using the GNU GPLv2 license (see NOTICE for the
exact license and exception used).

All documentation can be found on http://doc.powerdns.com/

This file may lag behind at times. For most recent updates, always check
https://doc.powerdns.com/md/changelog/.

Another good place to look for information is:
https://doc.powerdns.com/md/appendix/compiling-powerdns/

To file bugs, head towards:
https://github.com/PowerDNS/pdns/issues

But please check if the issue is already reported there first.

SOURCE CODE / GIT
-----------------
Source code is available on GitHub:

```
$ git clone https://github.com/PowerDNS/pdns.git
```

This repository contains the sources for the PowerDNS Recursor, the PowerDNS
Authoritative Server, and dnsdist (a powerful DNS loadbalancer). All three can
be built from this repository. However, all three released separately as .tar.bz2,
.deb and .rpm.

COMPILING Authoritative Server
------------------------------
The PowerDNS Authoritative Server depends on Boost, OpenSSL and requires a
compiler with C++-2011 support.

On Debian 8.0, the following is useful:

```
$ apt-get install g++ libboost-all-dev libtool make pkg-config libmysqlclient-dev libssl-dev
```

When building from git, the following packages are also required: autoconf, automake,
ragel, bison and flex, then generate the configure file:

```
$ ./bootstrap
```

To compile a very clean version, use:

```
$ ./configure --with-modules="" --without-lua
$ make
# make install
```

This generates a PowerDNS Authoritative Server binary with no modules built in.

When `./configure` is run without `--with-modules`, the bind and gmysql module are
built-in by default and the pipe-backend is compiled for runtime loading.

To add multiple modules, try:

```
$ ./configure --with-modules="bind gmysql gpgsql"
```

Note that you will need the development headers for PostgreSQL as well in this case.

See https://doc.powerdns.com/md/appendix/compiling-powerdns/ for more details.

If you run into C++11-related symbol trouble, please try passing `CPPFLAGS=-D_GLIBCXX_USE_CXX11_ABI=0` (or 1) to `./configure` to make sure you are compatible with the installed dependencies.

COMPILING THE RECURSOR
----------------------
See the README in pdns/recursordist.

COMPILING DNSDIST
----------------------
See the README in pdns/dnsdistdist.

SOLARIS NOTES
-------------
Use a recent gcc. OpenCSW is a good source, as is Solaris 11 IPS.

If you encounter problems with the Solaris make, gmake is advised.

FREEBSD NOTES
-------------
You need to compile using gmake - regular make only appears to work, but doesn't in fact. Use gmake, not make.

The clang compiler installed through FreeBSD's package manager does not expose all of the C++11 features needed under `std=gnuc++11`. Force the compiler to use `std=c++11` mode instead.

    export CXXFLAGS=-std=c++11

MAC OS X NOTES
--------------
PowerDNS Authoritative Server is available through Homebrew:

```
$ brew install pdns
```

If you want to compile yourself, the dependencies can be installed using
Homebrew:

```
$ brew install boost lua pkg-config ragel
```

For PostgreSQL support:

```
$ brew install postgresql
```

For MySQL support:

```
$ brew install mariadb
```

LINUX NOTES
-----------
None really.

NAMED CACHES NOTES
-----------
NamedCache general methods

      addNamedCache([strCacheName]) - create a named cache if it doesn't exist
                         - parameters:
                               strCacheName - cache name, defaults to "default"
                        - example: addNamedCache("yyy")
                        
      showNamedCaches() - display list of named caches on terminal
                        - example: showNamedCaches()

      closeNamedCache() - close a named cache, creates it if doesn't exist.
                          Used to free up resources used by a no longer needed cache
                          
      reloadNamedCache([strCacheNameA], [maxEntries])
                        - parameters:
                          [strCacheName] - named cache to reload - else "default"
                          [maxEntries]   - maxEntries if going to be changed, only 
                                           works if "bindToCDB" type named cache.
                        - example:reloadNamedCache("xxx")

NamedCacheX methods

      getNamedCache([strCacheName]) - get named cache object, create if not exist
                         - parameters:
                               strCacheName - cache name, defaults to "default"
                         - example:
                               ncx = getNamedCache("xxx")
                               
      getStats()         - get statistics in a table
                         - example:
                               tableStat2 = ncx:getStats()
                               
      showStats()        - directly print out statistics to console
                         - example:
                               getNamedCache("xxx"):showStats()
                               
      resetCounters()    - reset statistic counters for the named cache
                         - example:
                               getNamedCache("xxx"):resetCounters()
                               
      wasFileOpenedOK()  - return true if cdb file was opened OK
                         - example:
                               print(getNamedCache("xxx"):wasFileOpenedOK())
                               
      getErrNum()        - return error message number (errno, from last i/o operation)
                         - example:
                               print(getNamedCache("xxx"):getErrNum())
                               
      getErrMsg()        - return error message text
                         - example:
                               print(getNamedCache("xxx"):getErrMsg())
                               
      loadFromCDB()      - (re)initialize a new cache entirely into memory
                         - parameters:
                               strCacheName - cdb file path name to use
			              - returns:
                               true if everything went ok
                         - examples:
                               loadFromCDB("xxx.cdb")
                               
      bindToCDB(strCdbName, [maxEntries], [strMode]) - (re)initialize a new lru cache using a cdb file
                         - parameters:
                               strCdbName - cdb file path name to use
                               maxEntries - number of max entries to store in memory
                                         The default is 100000
                               strMode - "none", "cdb", "all"
                                         none - store nothing in memory
                                         cdb  - store cdb hits in memory
                                         all  - store all requests (even missed) in memory
                                         The default is "cdb"
			             - returns:
				              true if everything went ok
                         - examples:
                              loadFromCDB("xxx.cdb", "cdb", 200000)
                              loadFromCDB("xxx.cdb")  -- maxEntries = 100000, type="cdb"
                              
      getNamedCacheReasonText(strReason) - get reason text given string number - for debugging
                         - parameters:
                              strReason - 'integer' string from QTag field reason
			             - returns:
				              string with reason for cache hit
                         - example:
                              getNamedCacheReasonText(tResult.reason)
                              
      lookup(strQuery)   - use string with dns name & return lua readable table
                         - parameters:
                              strQuery -  string to lookup in named cache
                         - example:
                              iResult = getNamedCache("xxx"):lookup("bad.example.com")
                         - return lua table with QTag fields:
                              fields:
                                  found - one character string indicating if data found or not
                                          "T" - found with data
                                          "F" - not found, OR found without data
                                  reason - 'integer' value as string:
                                          CACHE_HIT::NOT_READY         - -1 (cache not read yet)
                                          CACHE_HIT::HIT_NONE          -  0 (match not found)
                                          CACHE_HIT::HIT_CDB           -  1 (match found in cdb file, data field not empty)
                                          CACHE_HIT::HIT_CACHE         -  2 (match found in cache, data field not empty)
                                          CACHE_HIT::HIT_CACHE_NO_DATA -  3 (match found in cache, empty data field)
                                          CACHE_HIT::HIT_CDB_NO_DATA   -  4 (match found in cdb file, empty data field)
                                  data - string from cdb table match
                                  
      lookupQ(DNSQuestion) - use DNSQuestion & addTag to store search results in DNSQuestion QTag object automatically
                             called inside lua subroutine setup with addLuaAction().
                           - QTag table can be read with lua function getTagArray() located inside lua function setup 
                             by RemoteLogAction() which is called before sending information out via protobuf.
                         - example:
                              iResult = getNamedCache("xxx"):lookupQ(dq)
                         - return lua table with QTag fields:
                              DNSQuestion QTag fields:
                                    Same as the fields for lookup() above.

example console commands:

* Create a named cache 

	addNamedCache("aaa")
    
* Bind the named cache to a cdb with default type ("cdb") and max entries (10000), print true if OK.

	print(getNamedCache("aaa"):bindToCDB("blocklist.cdb"))
    
* Bind the named cache to a cdb with specified type ("cdb") and specified max entries (200000), print true if OK.

	print(getNamedCache("aaa"):bindToCDB("blocklist.cdb", "cdb", 200000))
    
* Bind the named cache to a cdb with specified type - "all" - cache cdb & all attempts
  and default max entries (10000), print true if OK.
  
	print(getNamedCache("aaa"):bindToCDB("blocklist.cdb", "all", 200000))
    
* Load the entire cdb file into memory, print true if OK.

	print(getNamedCache("aaa"):loadFromCDB("blocklist.cdb"))
    
* Was the associated file for the named cache opened correctly?

	print(getNamedCache("aaa"):wasFileOpenedOK())
    
* Was there a named cache error - 0 is no error.

	print(getNamedCache("xxx"):getErrNum())
    
* Get the named cache error message - zero length string for no error.

	print(getNamedCache("xxx"):getErrMsg())
    
* Lookup an entry.

	test=getNamedCache("aaa"):lookup("1fuks551ut9x8d1gs9u801k0v9g7.net")
    
* See if there was a hit.

	print(string.format("%s",test.found))
    
* If there was a hit, see the associated data.

	print(string.format("%s",test.data))
    
* If there was a hit, see what kind it was.

	print(string.format("%s",test.reason))
    
* Get a text description of the reason.

	print(string.format("%s", getNamedCacheReasonText(test.reason)))
    
* Show statistics for a named cache on the console.

	getNamedCache("aaa"):showStats()
    
* Get statistics for a named cache in a table.

	tabX=getNamedCache("aaa"):getStats()
    
* Reset the statistic counters for a named cache.

	getNamedCache("aaa"):resetCounters()
    
* Reload a named cache.

	reloadNamedCache("aaa")
    
* Reload a named cache with a different number of max entries (only changes BindToCDB() max entries).

	reloadNamedCache("aaa", 23456)
    
* Close down the named cache.

	closeNamedCache("aaa")
    
* Show all named caches on the console.

	showNamedCaches()

-----------

Named Cache Test Compilation Notes:

The directory zzz-gca-example contains scripts, config files and other test items.

-----------

The following libraries were needed to be installed on Ubuntu 16.04
in order to run the build script: pdns/zzz-gca-example/build-dnsdist2-namedcache.sh
your system may differ.

libsodium-dev

ragel

libedit-dev

libboost-all-dev

lua5.1                  (version 5.1, higher versions may cause trouble?)

liblua5.1-dev           (version 5.1, higher versions may cause trouble?)

tinycdb                 (version 0.78)

libcdb-dev              (version 0.78)

protobuf-compiler       (this was not flagged by autoconf as missing.)

virtualenv              (this was not flagged by autoconf as missing.)

-----------

Compile dnsdist with the libsodium option (needed for protobuf use) and the named caches option enabled by running 
build-dnsdist2-namedcache.sh

-----------

For testing using the built in protobuf logger test program:

Install the following library: pip

Then after installing pip type: pip install protobuf

Ready the powerdns generic protobuf server by generating dnsmessage_pb2.py in pdns/contrib/ by following the instructions in the top couple lines of 
pdns/contrib/ProtobufLogger.py:
	run: protoc -I=../pdns/ --python_out=. ../pdns/dnsmessage.proto
    
 -----------
 
 A simple test of dnsdist witht he named cache software:

1. Open a console in pdns/zzz-gca-example and run ./protobuf-server2.sh

2. Open another console in pdns/zzz-gca-example and run ./dnsdist-named-cache-B.sh

3. Open another console in pdns/zzz-gca-example and run ./dig-test-nocookie.sh

   This should produce output in the protobuf server console similar to this (notice that the word FWD appears):

[2017-07-12 17:24:00.414274] Response of size 55: 127.0.0.1 -> 127.0.0.1 (UDP), id: 56469, uuid: 134f672434b34f36bef01ad48b06ec7b
- Question: 1, 1, google.com.
- Query time: 2017-07-12 17:24:00.395219
- Response Code: 0, RRs: 1, Tags: Trans, FWD
	 - 1, 1, google.com., 299, 172.217.7.174

4. From the same console used in step #3 run ./dig-test-nocookie.sh again

   This should produce output in the protobuf server console similar to this (notice that the word CACHE appears):

[2017-07-12 17:24:04.693645] Response of size 55: 127.0.0.1 -> 127.0.0.1 (UDP), id: 33312, uuid: 8aa92d90666d4007801c893cd2245a0b
- Question: 1, 1, google.com.
- Query time: 2017-07-12 17:24:04.693599
- Response Code: 0, RRs: 1, Tags: Trans, CACHE
	 - 1, 1, google.com., 295, 172.217.7.174

5. From the same console used in steps #3 and #4 and run ./dig-test-rpz.sh

   This should produce output in the protobuf server console similar to this (notice that the word RPZ appears):

[2017-07-12 17:24:26.907319] Response of size 56: 127.0.0.1 -> 127.0.0.1 (UDP), id: 48430, uuid: 59552d4fa7df4944ad1a949a0b970b54
- Question: 1, 1, 1jw2mr4fmky.net.
- Query time: 1969-12-31 19:00:00.0
- Response Code: 3, RRs: 1, Tags: lua-time, 17:24:26-07/12/17,Test1, One Two Three,lua-ver, Lua 5.1,Test2, Four Five Six,Trans, RPZ,RPZ-Info, dga,threatstop,From, 127.0.0.1:55350,TCP, false
	 - 1, 1, 1jw2mr4fmky.net., 456, 127.0.0.1

6. Further testing:
   Compile the utility gca_cdb_util at: https://github.com/GlobalCyberAlliance/gca_cdb_util.git

   This utility can make cdb files and test operation localy of dnsdist.
   To test out local operation of dnsdist, run the 'T' or 'U' commands.

   Options 'B', 'C' and 'E' are usefull ones for building cdb files.

   To change the configuration parameters of the utility, modify the file config.txt which should be in the same directory as gca_cdb_util
   

   To maximize transaction speed you can run ./protobuf-server-alt.sh which starts the protobuf server with no console output in place of the normal one.
   The python code is located in: pdsn/zzz-gca-example/ProtobufServerAlt and is pretty much a copy of the standard one in contrib/ProtobufLogger.py which
   most of text processing commented out.

 -----------

Files that got modifed for the named cache version of dnsdist:

	dnsdist-lua.cc      - lua interface functions
	dnsdist-lua2.cc     - lua interface functions
    dnsdist.cc          - contains class NamedCacheX and g_namedCaches for map of NamedCaches

Files that are new (also *.hh associated files):

	dnsdist-cdbio.cc              - read cdb file object
	dnsdist-namedcache.cc         - class for a named-cache
 	dnsdist-nc-lrucache.cc        - lru (Least Recently Used) cache object, 
                                    new version using std::list & std::unorderedmap
	dnsdist-nc-lrucache2.cc       - lru (Least Recently Used) cache object 
                                    using own DoublyLinkedList object.
	dnsdist-nc-mapcache.cc        - map cache object
	dnsdist-nc-namedcache.cc      - mostly virtual functions
	dnsdist-nc-nocache.cc         - no cache (does nothing) & no cache cdb (just cdb)
    
-----------

All new lua commands for named caches (10/10/2017) are located in dnsdist-lua2.cc starting at line 725

A grep for "GCA" works for getting quickly to modified code segments, except for code in the "new" files listed above.

-----------

Important files:

	build-dnsdist2-namedcache.sh - script to build dnsdist with libsodium and named cache options enabled.

	./make-dnsdist2.sh           - make file to recompile dnsdist without doing an entire build - 
                                   need to have run ./build-dnsdist2-namedcache.sh at least once before.

	dnsdist-namedcache-B.conf    - 10/4/2017 demonstration config file for dnsdist that uses protobuf and named caches.

    ./dnsdist-namedcache-B.sh    - 10/4/2017 launch dnsdist using the dnsdist-namedcache-B.conf configuration file.

	build-dnsdist2.sh            - build dnsdist with the libsodium option enabled - needed for protobuf operation.

	./protobuf-server2.sh        - launch the generic protobuf server which is in pdns/contrib 

	./protobuf-server-alt.sh     - launch the modified generic protobuf server which is in 
                                   pnds/zzz-gca-example/ProtobufServerAlt that has no console output for more speed.

	./dig-test-nocookie.sh       - script to send a regular request to dnsdist, 
                                   no cookie option was needed to work with old dnsdist cache bug (fixed now)

	./dig-test-nocookie2.sh      - script to send a regular request to dnsdist, 
                                   no cookie option was needed to work with old dnsdist cache bug (fixed now)

	./dig-test-rpz.sh            - script to send a rpz request to dnsdist.

	./test-all.sh                - script to call all regression tests for dnsdist.

	./test-protobuf.sh           - script to call only the regression test for the protobuf module in dnsdist.

	./test-tinycdb.lua           - lua code to test the operation of lua, tinycdb and the cdb database together.

	dnsdist.conf                 - config file for dnsdist that does not use tinycdb for simple demonstration.

	dnsdist2-complex.conf        - config file for dnsdist that uses tinycdb for accessing rpz database.

	dnsdist-namedcache.conf      - outdated demonstration config file for dnsdist that uses protobuf and named caches.
 
-----------

Why you want want to keep track of ‘missed’ hits in a rpz named cache using a lru method:

Lets say you are using a lru named cache in dnsdist which you set up something like this:

getNamedCache(“xxx”):bindToCDB(“zzz.cdb”, 10000, “cdb”) 

It will only populate the lru cache with hits from the zzz.cdb file.  The problem is that if you are using the named cache to look for rpz hits which should make up a small percentage of the total dns lookups which are mostly valid.  The net effect of this will be to cause a typical lookup to not appear in the lru cache and the rpz cdb file will have to be searched before failing for a valid dns lookup.  The way to get around this is to store all lookups presented to the named cache.  If they are not found in either the lru cache or the associated cdb file a new entry with an empty data field should be stored in the lru cache.  Since all rpz entries in the cdb file contain a data field it is easy to distinguish between rpz hits and those hits that appear in the named cache that should be sent on to a normal lookup by a dns server.

The way to setup the lru named cache for use with a rpz file should be something like this:

getNamedCache(“xxx”):bindToCDB(“zzz.cdb”, 10000, "all") 

now the named cache will have entries from all requests with a much less frequent read of the actual cdb file.

If you are storing the entire rpz cdb file in memory with something like this:

getNamedCache(“yyy):loadFromCDB(“zzz.cdb”)

This isn’t a problem as if the rpz entry doesn’t exist in the cache, you just go and do a normal dns lookup with little loss in performance.

-----------

Example lua code found in the dnsdist configuration file,
please study pdns/zzz-gca-example/dnsdist-named-cache-B.conf:


An example of Lua code in dnsdist configuration file to setup a named cache:

     ncx = getNamedCache("xxx")	-- create a named cache called xxx,
						        -- set ncx to the NamedCacheX object

	strCDB = "../db/blocklist.cdb"	-- declare string to location of cdb file
						
    ncx:bindToCDB(strCDB)       -- initialize named cache

	ncx:showStats()			-- show statistics for object ncx
						
-----------


Example of looking for match in rpz db in the dnsdist configuration file:


    function luaCheckBL(dq)

        local tResult = getNamedCache("xxx"):lookupQ(dq)

        print(string.format("luaCheckBL ->lookupQ called"))
        print(string.format("found.: %s ", tResult.found))
        print(string.format("reason: %s  (%s)", tResult.reason, getNamedCacheReasonText(tResult.reason)))
        print(string.format("data..: %s ", tResult.data))

	    if(tResult.found == "T")
         then
            return DNSAction.None, ""        -- cache hit, continue on to next rule
         end

	return DNSAction.Pool, "masterpool"		-- use the specified pool to forward this query

-----------

Example of sending rpz match data out to protobuf:


function luaLogBL(dr, pbMsg)		            -- this is the lua code that executes for a request
              
    local tableTags = dr:getTagArray()	        -- get array of tags 

    pbMsg:setTagArray(tableTags)		        -- store tableTags in the 'tags' field of the protobuf
 
    pbMsg:setResponseCode(dnsdist.NXDOMAIN)     -- set protobuf resp code to be NXDOMAIN

    local strReqName = dr.qname:toString()	    -- get request dns name

    pbMsg:setProtobufResponseType()	   	        -- set time, but no RR - no seconds or uSec values


    blobData = '\127' .. '\000' .. '\000' .. '\001' -- 127.0.0.1, note: lua 5.1only embed dec not hex

    pbMsg:addResponseRR(strReqName, 1, 1, 456, blobData)    
						-- set protobuf to look like response and not query
						-- rr type  1 - ‘A’ ,  a 32 bit type ipv4 address 
						-- rr class 1 -  internet address
						-- rr ttl	- time-to-live in seconds
						-- rr blob data  - the 32 bit ipv4 hex address

    end
    
    
    

Example of rules in dnsdist configuration file to set up rpz checking:


addLuaAction(AllRule(), luaCheckBL)	-- first, check blacklist, if match process next rule below, else send to "masterpool"
						                                

						                
addAction(AllRule(), RemoteLogAction(rlBlkLst, luaLogBL))   -- send out protobuf for rpz hit 

						                
addLuaAction(AllRule(), luaRetNXDOMAIN)  -- then send nxdomain response back to the client.      

						                	
addAction(AllRule(), PoolAction("masterpool"))	-- direct req that are not RPZ to pool "masterpool"	    

						                
addCacheHitResponseAction(AllRule(), RemoteLogResponseAction(rlCache, luaLogCache))	 -- send out protobuf on reg cache hit 

 						                
addResponseAction(AllRule(), RemoteLogResponseAction(rlFwd, luaLogForward))	-- send out protobuf on forward (normal) out 	

