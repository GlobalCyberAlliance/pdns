#! /usr/bin/env lua5.1
-- need this example to work with lua 5.1 as that is what dnsdist uses.

-- -----------------------------------------------------------------------------
-- -----------------------------------------------------------------------------

       strCPackage = "lua-tinycdb-0.2-modified-Makefile"        -- where cdb library is located
       strLibrary  = "cdb"                                      -- the name of the tinycdb library
       strDatabase = "CDB_Database/blocklist.cdb"		-- location of cdb database
       strTestName = "1jw2mr4fmky.net"                          -- test dns lookup name

       print(string.format("Test to verify lua-tinycdb operation with blocklist.cdb  5/15/2015"))
       print(string.format("Seth Ornstein     Global Cyber Alliance"))
       print(string.format("NOTE: Currently dnsdist uses version 5.1 of Lua!!!"))
       print(string.format("      The tinycdb library must work with this version!!"))
       print(string.format(""))

       print(string.format("Lua Version: %s ", _VERSION))
       print(string.format(""))

       print(string.format("C package path addition.: %s", strCPackage))
 
       package.cpath = package.cpath .. ';' .. strCPackage .. '/?.so'

       print(string.format("Load tinycdb library....: %s", strLibrary))

       cdb = require(strLibrary)                -- load the tinycdb library

       print(string.format("Open the cdb database at: %s", strDatabase))
       print(string.format(""))

       db = cdb.open(strDatabase)		-- open the database

       print(string.format("Lookup name..: %s ", strTestName))

       local entryFound = db:get(strTestName)   -- lookup name in database

       if (entryFound == nil)
       then
           print(string.format("No entry found!!!"))
       else
           print(string.format("Found entry..: %s", entryFound))
       end
       print(string.format(""))

       local iCounter = 0                       -- count entries in database
       for k, v in db:pairs() do
          iCounter = iCounter + 1
       end

       print(string.format("Entries in db: %d ", iCounter))
       print(string.format(""))

-- outputs:
--
-- key  value
-- foo  bar
-- foo  baz
-- baz  qux

--[[
       -- display all pairs in the database
       for k, v in db:pairs() do
           print(k, v)
       end
--]]
 
--[[
       -- find_all returns a table of all values for the given key
       local t = db:find_all(strTestName)      -- t = { "bar", "baz" }
--]]

       db:close()                              -- close the database

       print(string.format("Finished."))
