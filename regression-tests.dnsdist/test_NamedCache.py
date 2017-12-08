#!/usr/bin/env python
import Queue
import threading
import socket
import struct
import sys
import time
from dnsdisttests import DNSDistTest

import dns
import dnsmessage_pb2


import os, sys 



# cdb library for python
# from: https://code.google.com/archive/p/tinycdb-python/

import ctypes
from ctypes import *
from ctypes.util import find_library

if sys.platform == 'win32':
    cdblib = cdll.LoadLibrary("libcdb.dll")
else:
    cdblib = cdll.LoadLibrary("libcdb.so")


CDB_PUT_ADD = 0
CDB_FIND = CDB_PUT_ADD
CDB_PUT_REPLACE = 1
CDB_FIND_REMOVE = CDB_PUT_REPLACE
CDB_PUT_INSERT = 2
CDB_PUT_WARN = 3
CDB_PUT_REPLACE0 = 4
CDB_FIND_FILL0 = CDB_PUT_REPLACE0

class cdb (Structure):
    _fields_ = [('cdb_fd', c_int),
                ('cdb_fsize', c_uint),
                ('cdb_dend', c_uint),
                ('cdb_men', c_char_p),
                ('cdb_vpos', c_uint),
                ('cdb_vlen', c_uint),
                ('cdb_kpos', c_uint),
                ('cdb_klen', c_uint)]

class cdb_rec (Structure):
    _fields_ = [('hval', c_uint),
                ('rpos', c_uint)]


class cdb_rl (Structure):
    pass
cdb_rl._fields_ = [('next', POINTER(cdb_rl)),
                ('cnt', c_uint),
                ('rec', cdb_rec * 254)]


class cdb_find (Structure):
    _fields_ = [('cdb_cdbp', POINTER(cdb)),
                ('cdb_hval', c_uint),
                ('cdb_htp', c_char_p),
                ('cdb_htab', c_char_p),
                ('cdb_htend', c_char_p),
                ('cdb_httodo', c_uint),
                ('cdb_key', c_void_p),
                ('cdb_klen', c_uint)]

class cdb_make (Structure):
    _fields_ = [('cdb_fd', c_int),
                ('cdb_dpos', c_uint),
                ('cdb_cdb_rcnt', c_uint),
                ('cdb_cdb_buf', c_ubyte * 4096),
                ('cdb_bpos', POINTER(c_ubyte)),
                ('cdb_rec', POINTER(cdb_rl) * 256)]


cdblib.cdb_make_start.argtypes = [POINTER(cdb_make), c_int]
cdblib.cdb_make_add.argtypes = [POINTER(cdb_make), c_void_p, c_uint, c_void_p, c_uint]
cdblib.cdb_make_put.argtypes = [POINTER(cdb_make), c_void_p, c_uint, c_void_p, c_uint, c_uint]
cdblib.cdb_make_exists.argtypes = [POINTER(cdb_make), c_void_p, c_uint]
cdblib.cdb_make_finish.argtypes = [POINTER(cdb_make)]

cdblib.cdb_findinit.argtypes = [POINTER(cdb_find), POINTER(cdb), c_void_p, c_uint]
cdblib.cdb_findnext.argtypes = [POINTER(cdb_find)]
cdblib.cdb_seqnext.argtypes = [c_uint, POINTER(cdb)]
cdblib.cdb_seek.argtypes  = [c_int, c_void_p, c_uint, POINTER(c_uint)]
cdblib.cdb_bread.argtypes = [c_int, c_void_p, c_int]

cdblib.cdb_init.argtypes = [POINTER(cdb), c_int]
cdblib.cdb_free.argtypes = [POINTER(cdb)]
cdblib.cdb_read.argtypes = [POINTER(cdb), c_void_p, c_uint, c_uint]
cdblib.cdb_get.argtypes  = [POINTER(cdb), c_uint, c_uint]
cdblib.cdb_find.argtypes = [POINTER(cdb), c_void_p, c_uint]

cdblib.cdb_hash.argtypes = [c_void_p, c_uint]
cdblib.cdb_unpack.argtypes = [POINTER(c_ubyte)]
cdblib.cdb_pack.argtypes = [c_uint, POINTER(c_ubyte)]

def cdb_datapos(c):
    return c.cdb_vpos

def cdb_datalen(c):
    return c.cdb_vlen

def cdb_keypos(c):
    return c.cdb_kpos

def cdb_keylen(c):
    return c.cdb_klen

def cdb_fileno(c):
    return c.cdb_fd


class CDB:
    def __init_(self):
        pass


class Maker:
    def __init__(self, filename):
        self.cdbm = cdb_make()
        self.file = open(filename, 'w')
        self.fd = self.file.fileno()
        cdblib.cdb_make_start(self.cdbm, self.fd)

    def add(self, key, val):
        cdblib.cdb_make_add(self.cdbm, key, len(key), val, len(val)) 


    def put(self, key, val, flags):
        cdblib.cdb_make_put(self.cdbm, key, len(key), val, len(val), flags) 
    

    def __setitem__(self, key, val):
        cdblib.cdb_make_add(self.cdbm, key, len(key), val, len(val)) 
        

    def finish(self):
        cdblib.cdb_make_finish(self.cdbm)

    def close(self):
        self.finish()


class Finder:
    def __init__(self, filename):
        self.file = open(filename, 'r')
        self.fd = self.file.fileno()
        self.cdb = cdb()
        
        cdblib.cdb_init(self.cdb, self.fd)
    
    def __getitem__(self, key):
        ret = self.find(key)
        if ret is None:
            raise IndexError, 'not found ' + key
        return ret

    def find(self, key):
        ret = cdblib.cdb_find(self.cdb, key, len(key))
        if ret > 0:
            vpos = cdb_datapos(self.cdb)
            vlen = cdb_datalen(self.cdb)

            buf = (c_char * vlen)()
            val = cast(buf, c_void_p)

            cdblib.cdb_read(self.cdb, val, vlen, vpos)

            return buf.value
        else:
            return None
 
    def findall(self, key):
        retv = []
        finder = cdb_find()
        cdblib.cdb_findinit(finder, self.cdb, key, len(key))
        while cdblib.cdb_findnext(finder) > 0:
            vpos = cdb_datapos(self.cdb)
            vlen = cdb_datalen(self.cdb)

            buf = (c_char * vlen)()
            val = cast(buf, c_void_p)

            cdblib.cdb_read(self.cdb, val, vlen, vpos)

            retv.append(buf.value)

        return retv


    def seek(self, key):
        vlen = c_uint()
        ret = cdblib.cdb_seek(self.fd, key, len(key), vlen)
        if ret > 0:
            buf = (c_char * vlen.value)()
            val = cast(buf, c_void_p)

            cdblib.cdb_bread(self.fd, val, vlen.value)
            return buf.value
        else:
            return None


    def close(self):
        cdblib.cdb_free(self.cdb)
        self.file.close()

# create test cdb file
def create_cdb():
    m = Maker('test.cdb')

    m['1fuks551ut9x8d1gs9u801k0v9g7.net'] = 'rpz-test-1'
    m['1funvaz1momy1vruganraqwii7.org'] = 'rpz-test-1'
    m['1fuyfus16emwaj4b253a15gbh9c.org'] = 'rpz-test-1'
    m['azurewebsites.net'] = 'rpz-test-1'
    m['zziemjfgdu.nightmichael.top'] = 'rpz-test-1'
    m['lua.protobuf.tests.powerdns.com'] = 'rpz-test-1'

    m.close()

def delete_cdb():

    os.remove('test.cdb')

class TestNamedCache(DNSDistTest):
    create_cdb()                                                # create test cdb file first
    _protobufServerPort = 4242
    _protobufQueue = Queue.Queue()
    _protobufCounter = 0
    _config_params = ['_testServerPort', '_protobufServerPort']
    _config_template = """					-- start of the lua code
    luasmn = newSuffixMatchNode()
    luasmn:add(newDNSName('lua.protobuf.tests.powerdns.com.'))

    function alterProtobufResponse(dq, protobuf)
      if luasmn:check(dq.qname) then
        requestor = newCA(dq.remoteaddr:toString())		-- called by testLuaProtobuf()
        if requestor:isIPv4() then
          requestor:truncate(24)
        else
          requestor:truncate(56)
        end
        protobuf:setRequestor(requestor)
        local tableTags = {}
        table.insert(tableTags, "TestLabel1,TestData1")
        table.insert(tableTags, "TestLabel2,TestData2")
        protobuf:setTagArray(tableTags)
        protobuf:setTag('TestLabel3,TestData3')
        protobuf:setTag("Response,456")
        protobuf:setTag("found,no")				-- need to inject this field..... 12/3/2017
      else
        local tableTags = {} 					-- called by testProtobuf()
        table.insert(tableTags, "TestLabel1,TestData1")
        table.insert(tableTags, "TestLabel2,TestData2")
        protobuf:setTagArray(tableTags)
        protobuf:setTag('TestLabel3,TestData3')
        protobuf:setTag("Response,456")
        protobuf:setTag("found,no")				-- need to inject this field..... 12/8/2017
      end
    end

    function alterProtobufQuery(dq, protobuf)
      if luasmn:check(dq.qname) then
        requestor = newCA(dq.remoteaddr:toString())		-- called by testLuaProtobuf()
        if requestor:isIPv4() then
          requestor:truncate(24)
        else
          requestor:truncate(56)
        end
        protobuf:setRequestor(requestor)

        local tableTags = {}
        tableTags = dq:getTagArray()				-- get table from DNSQuery

        local tablePB = {}
          for k, v in pairs( tableTags) do
          table.insert(tablePB, k .. "," .. v)
        end

        protobuf:setTagArray(tablePB)				-- store table in protobuf
        protobuf:setTag("Query,123")				-- add another tag entry in protobuf

        protobuf:setTag("found,yes")				-- need to inject this field..... 12/3/2017

        protobuf:setResponseCode(dnsdist.NXDOMAIN)        	-- set protobuf response code to be NXDOMAIN

        local strReqName = dq.qname:toString()		  	-- get request dns name

        protobuf:setProtobufResponseType()			-- set protobuf to look like a response and not a query, with 0 default time

        blobData = '\127' .. '\000' .. '\000' .. '\001'		-- 127.0.0.1, note: lua 5.1 can only embed decimal not hex

        protobuf:addResponseRR(strReqName, 1, 1, 123, blobData) -- add a RR to the protobuf

        protobuf:setBytes(65)					-- set the size of the query to confirm in checkProtobufBase
      else

        local tableTags = {}                                    -- called by testProtobuf()
        table.insert(tableTags, "TestLabel1,TestData1")
        table.insert(tableTags, "TestLabel2,TestData2")

        protobuf:setTagArray(tableTags)
        protobuf:setTag('TestLabel3,TestData3')
        protobuf:setTag("Query,123")

        protobuf:setTag("found,no")				-- need to inject this field..... 12/3/2017
      end
    end

    function alterLuaFirst(dq)					-- called when dnsdist receives new request
      local tt = {}
      tt["TestLabel1"] = "TestData1"
      tt["TestLabel2"] = "TestData2"

      dq:setTagArray(tt)

      dq:setTag("TestLabel3","TestData3")
      return DNSAction.None, ""					-- continue to the next rule
    end

    function checkNamedCache(dq)
      statTable = getNamedCache("xxx"):getStats()
      local result = getNamedCache("xxx"):lookupQ(dq)		
      if result.found then
         m = newDNSDistProtobufMessage(dq)                      -- matching entry was found in cdb
     
         local tableTags = dq:getTagArray()
         local tablePB = {}
         for k, v in pairs( tableTags) do
           table.insert(tablePB, k .. ", " .. v)
         end
     
         local strReqName = dq.qname:toString()
         blobData = '\127' .. '\000' .. '\000' .. '\001'
     
         m:setProtobufResponseType()
         m:addResponseRR(strReqName, 1, 1, 456, blobData)
    
         requestor = newCA(dq.remoteaddr:toString())		-- called by testLuaProtobuf()
         if requestor:isIPv4() then
          requestor:truncate(24)
         else
          requestor:truncate(56)
         end
         m:setRequestor(requestor)

         local tableTags = {}                                    -- called by testProtobuf()
         table.insert(tableTags, "TestLabel1,TestData1")
         table.insert(tableTags, "TestLabel2,TestData2")

         m:setTagArray(tableTags)
         m:setTag('TestLabel3,TestData3')
         m:setTag("Query,123")
         m:setTag("found,yes")
 
         m:setResponseCode(dnsdist.NXDOMAIN)
         m:setProtobufResponseType()

         ---m:addResponseRR(strReqName, 1, 1, 456, blobData)

         remoteLog(rl, m)                                       -- send out protobuf

          return DNSAction.Spoof, "1.2.3.4"			-- spoof test, only 1 protobuf msg, no dns query

      end
      return DNSAction.None, ""			                -- allow rule processing to continue
    end

    newServer{address="127.0.0.1:%s", useClientSubnet=true}

    rl = newRemoteLogger('127.0.0.1:%s')                      -- protobuf server 

    xxx = getNamedCache("xxx"):loadFromCDB("test.cdb")        -- load test cdb into named cache

    addLuaAction(AllRule(), checkNamedCache)		      -- check if named cache hit

    addResponseAction(AllRule(), RemoteLogResponseAction(rl, alterProtobufResponse, true))	-- Send protobuf message after lookup

    """

    @classmethod
    def ProtobufListener(cls, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the protbuf listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            (conn, _) = sock.accept()
            data = None
            while True:
                data = conn.recv(2)
                if not data:
                    break
                (datalen,) = struct.unpack("!H", data)
                data = conn.recv(datalen)
                if not data:
                    break

                cls._protobufQueue.put(data, True, timeout=2.0)

            conn.close()
        sock.close()

    @classmethod
    def startResponders(cls):
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

        cls._protobufListener = threading.Thread(name='Protobuf Listener', target=cls.ProtobufListener, args=[cls._protobufServerPort])
        cls._protobufListener.setDaemon(True)
        cls._protobufListener.start()

    def getFirstProtobufMessage(self):
        self.assertFalse(self._protobufQueue.empty())
        data = self._protobufQueue.get(False)
        self.assertTrue(data)
        msg = dnsmessage_pb2.PBDNSMessage()
        msg.ParseFromString(data)
        return msg

    def checkProtobufBase(self, msg, protocol, query, initiator, normalQueryResponse=True):
        self.assertTrue(msg)
        self.assertTrue(msg.HasField('timeSec'))
        self.assertTrue(msg.HasField('socketFamily'))
        self.assertEquals(msg.socketFamily, dnsmessage_pb2.PBDNSMessage.INET)
        self.assertTrue(msg.HasField('from'))
        fromvalue = getattr(msg, 'from')
        self.assertEquals(socket.inet_ntop(socket.AF_INET, fromvalue), initiator)
        self.assertTrue(msg.HasField('socketProtocol'))
        self.assertEquals(msg.socketProtocol, protocol)
        self.assertTrue(msg.HasField('messageId'))
        self.assertTrue(msg.HasField('id'))
        self.assertEquals(msg.id, query.id)
        self.assertTrue(msg.HasField('inBytes'))
        if normalQueryResponse:
          # compare inBytes with length of query/response
          self.assertEquals(msg.inBytes, len(query.to_wire()))

    def checkProtobufQuery(self, msg, protocol, query, qclass, qtype, qname, initiator='127.0.0.1'):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSQueryType)
        self.checkProtobufBase(msg, protocol, query, initiator)
        # dnsdist doesn't fill the responder field for responses
        # because it doesn't keep the information around.
        self.assertTrue(msg.HasField('to'))
        self.assertEquals(socket.inet_ntop(socket.AF_INET, msg.to), '127.0.0.1')
        self.assertTrue(msg.HasField('question'))
        self.assertTrue(msg.question.HasField('qClass'))
        self.assertEquals(msg.question.qClass, qclass)
        self.assertTrue(msg.question.HasField('qType'))
        self.assertEquals(msg.question.qClass, qtype)
        self.assertTrue(msg.question.HasField('qName'))
        self.assertEquals(msg.question.qName, qname)

    def checkProtobufTags(self, tags, expectedTags):
        # only differences will be in new list
        listx = set(tags) ^ set(expectedTags)
        # exclusive or of lists should be empty
        strErrMsg = "Protobuf tags don't match: %s ----> %s" % (listx, tags)
        self.assertEqual(len(listx), 0, strErrMsg)

    def checkProtobufQueryConvertedToResponse(self, msg, protocol, response, initiator='127.0.0.0'):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        self.checkProtobufBase(msg, protocol, response, initiator, False)
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))

    def checkProtobufResponse(self, msg, protocol, response, initiator='127.0.0.1'):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        self.checkProtobufBase(msg, protocol, response, initiator)
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))

    def checkProtobufResponseRecord(self, record, rclass, rtype, rname, rttl):
        self.assertTrue(record.HasField('class'))
        self.assertEquals(getattr(record, 'class'), rclass)
        self.assertTrue(record.HasField('type'))
        self.assertEquals(record.type, rtype)
        self.assertTrue(record.HasField('name'))
        self.assertEquals(record.name, rname)
        self.assertTrue(record.HasField('ttl'))
        self.assertEquals(record.ttl, rttl)
        self.assertTrue(record.HasField('rdata'))

# start of python execution 


    # test named cache lookup 'match'
    def testLuaNamedCacheMatch(self):
        """
        Protobuf: Check that the Lua callback rewrote the initiator
        """

        name = 'lua.protobuf.tests.powerdns.com.'			# dns name to lookup and match.....
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)


        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response) # send out the UDP query

        self.assertTrue(receivedResponse)

        
        time.sleep(1)								# let the protobuf messages the time to get there

        									# check the protobuf message corresponding to the UDP query
        msg = self.getFirstProtobufMessage()

        self.checkProtobufQueryConvertedToResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response, '127.0.0.0')

        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Query,123", u"found,yes"])  


        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedResponse)
        									# let the protobuf messages the time to get there
        time.sleep(1)

        									# check the protobuf message corresponding to the TCP query
        msg = self.getFirstProtobufMessage()

        self.checkProtobufQueryConvertedToResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, response, '127.0.0.0')

        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Query,123", u"found,yes"])


    # test named cache lookup 'no match'
    def testLuaNamedCacheNoMatch(self):
        """
        Protobuf: Check that the Lua callback rewrote the initiator
        """

        name = 'xxxxlua.protobuf.tests.powerdns.com.'			# dns name to lookup and match.....
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)


        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response) # send out the UDP query

        self.assertTrue(receivedResponse)

        
        time.sleep(1)								# let the protobuf messages the time to get there

        									# check the protobuf message corresponding to the UDP query
        msg = self.getFirstProtobufMessage()

        self.checkProtobufQueryConvertedToResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response, '127.0.0.1')	              # was 127.0.0.0

        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Response,456", u"found,no"])  


#        sys.stderr.write("\n***** testLuaNamedCacheMatch() - get 2nd protobuf message ***** \n")
         									# check the protobuf message corresponding to the UDP response
#        msg = self.getFirstProtobufMessage()

#        sys.stderr.write("\n***** testLuaNamedCacheMatch() - got 2nd protobuf message ***** \n")

#        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response, '127.0.0.0')

#        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Response,456"])

#        self.assertEquals(len(msg.response.rrs), 1)
#        for rr in msg.response.rrs:
#            self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 3600)
#            self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')



        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedResponse)
        									# let the protobuf messages the time to get there
        time.sleep(1)

        									# check the protobuf message corresponding to the TCP query
        msg = self.getFirstProtobufMessage()

        self.checkProtobufQueryConvertedToResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, response, '127.0.0.1')               # was 127.0.0.0

        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Response,456", u"found,no"])


    def testCreateCDBxxxxx(self):
        delete_cdb()


