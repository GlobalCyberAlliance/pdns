#!/usr/bin/env python2

import binascii
import datetime
import socket
import struct
import sys
import threading

# run: protoc -I=../pdns/ --python_out=. ../pdns/dnsmessage.proto
# to generate dnsmessage_pb2
import dnsmessage_pb2




# ------------------------------------------------------------------------------
# Seth - from: http://stackoverflow.com/questions/35088139/how-to-make-a-thread-safe-global-counter-in-python
# ------------------------------------------------------------------------------

from multiprocessing import Process, RawValue, Lock
import time

class Counter(object):
    def __init__(self, value=0):
        # RawValue because we don't need it to create a Lock:
        self.val = RawValue('i', value)
        self.lock = Lock()

    def increment(self):
        with self.lock:
            self.val.value += 1

    def value(self):
        with self.lock:
            return self.val.value

# ------------------------------------------------------------------------------

thread_safe_counter = Counter(0)            # Seth - counter
query_counter = Counter(0)
resp_counter = Counter(0)
out_query_counter = Counter(0)
in_resp_counter = Counter(0)
bad_msg_counter = Counter(0)

debug = -1

# ------------------------------------------------------------------------------

class PDNSPBConnHandler(object):

    def __init__(self, conn):
        self._conn = conn

    def run(self):
        while True:
            data = self._conn.recv(2)
            if not data:
                break


            (datalen,) = struct.unpack("!H", data)
            data = self._conn.recv(datalen)

            thread_safe_counter.increment()		# increment total count

	    if debug < 0:
	    	if thread_safe_counter.value() % 100000 == 0:
            		print('------>   Total: %d  ' % (thread_safe_counter.value()))
		continue

            msg = dnsmessage_pb2.PBDNSMessage()
            msg.ParseFromString(data)
    
        
	    if thread_safe_counter.value() % 100000 == 0:
            	print('------>   Total: %d   Query: %d   Resp: %d   OutQuery: %d   InResp: %d ' % (thread_safe_counter.value(), query_counter.value(), resp_counter.value(), out_query_counter.value(), in_resp_counter.value()))

            if msg.type == dnsmessage_pb2.PBDNSMessage.DNSQueryType:
                self.printQueryMessage(msg)
            elif msg.type == dnsmessage_pb2.PBDNSMessage.DNSResponseType:
                self.printResponseMessage(msg)
            elif msg.type == dnsmessage_pb2.PBDNSMessage.DNSOutgoingQueryType:
                self.printOutgoingQueryMessage(msg)
            elif msg.type == dnsmessage_pb2.PBDNSMessage.DNSIncomingResponseType:
                self.printIncomingResponseMessage(msg)
            else:
                bad_msg_counter.increment()
                print('Discarding unsupported message type %d' % (msg.type))

        self._conn.close()

    def printQueryMessage(self, message):
        query_counter.increment()
	if debug > 0:
        	self.printSummary(message, 'Query')
        	self.printQuery(message)

    def printOutgoingQueryMessage(self, message):
        out_query_counter.increment()
	if debug > 0:
        	self.printSummary(message, 'Query (O)')
        	self.printQuery(message)

    def printResponseMessage(self, message):
        resp_counter.increment()
	if debug > 0:
        	self.printSummary(message, 'Response')
        	self.printQuery(message)
        	self.printResponse(message)

    def printIncomingResponseMessage(self, message):
        in_resp_counter.increment()
	if debug > 0:
        	self.printSummary(message, 'Response (I)')
        	self.printQuery(message)
        	self.printResponse(message)

    def printQuery(self, message):
        if message.HasField('question'):
            qclass = 1
            if message.question.HasField('qClass'):
                qclass = message.question.qClass
	    if debug > 0:
            	print("- Question: %d, %d, %s" % (qclass,
                                              message.question.qType,
                                              message.question.qName))

    def printResponse(self, message):
        if message.HasField('response'):
            response = message.response

            if response.HasField('queryTimeSec'):
                datestr = datetime.datetime.fromtimestamp(response.queryTimeSec).strftime('%Y-%m-%d %H:%M:%S')
                if response.HasField('queryTimeUsec'):
                    datestr = datestr + '.' + str(response.queryTimeUsec)
		if debug > 0:
               	    print("- Query time: %s" % (datestr))

            policystr = ''
            if response.HasField('appliedPolicy') and response.appliedPolicy:
                policystr = ', Applied policy: ' + response.appliedPolicy

            tagsstr = ''
            if response.tags:
               tagsstr = ', Tags: ' + ','.join(response.tags)

            rrscount = len(response.rrs)

	    if debug > 0:
            	print("- Response Code: %d, RRs: %d%s%s" % (response.rcode,
                                                      rrscount,
                                                      policystr,
                                                      tagsstr))
 


            for rr in response.rrs:
                rrclass = 1
                rdatastr = ''
                if rr.HasField('class'):
                    rrclass = getattr(rr, 'class')
                rrtype = rr.type
                if (rrclass == 1 or rrclass == 255) and rr.HasField('rdata'):
                    if rrtype == 1:
                        rdatastr = socket.inet_ntop(socket.AF_INET, rr.rdata)
                    elif rrtype == 5:
                        rdatastr = rr.rdata
                    elif rrtype == 28:
                        rdatastr = socket.inet_ntop(socket.AF_INET6, rr.rdata)

		if debug > 0:
                	print("\t - %d, %d, %s, %d, %s" % (rrclass,
                                                   rrtype,
                                                   rr.name,
                                                   rr.ttl,
                                                   rdatastr))

 ## Seth - GCA - parse tags - 5/24/2017

		if debug > 0:
            		if response.tags:                         
               			indexval = 0
               			print("##        LABEL              VALUE")
               			print("--   ---------------   -----------------")
               			for i in range(len(response.tags)):     
                  			strPairs = response.tags[indexval].split(",", 1)
                  			strLabel = ""
                  			strValue = ""
                  			if (len(strPairs) > 0):
                     				strLabel = strPairs[0]
                  			if (len(strPairs) > 1):
                     				strValue = strPairs[1]
                  			print("%2d   %-15s   %s" % (indexval, strLabel, strValue))
                  			indexval += 1




    def printSummary(self, msg, typestr):
        datestr = datetime.datetime.fromtimestamp(msg.timeSec).strftime('%Y-%m-%d %H:%M:%S')
        if msg.HasField('timeUsec'):
            datestr = datestr + '.' + str(msg.timeUsec)
        ipfromstr = 'N/A'
        iptostr = 'N/A'
        fromvalue = getattr(msg, 'from')
        if msg.socketFamily == dnsmessage_pb2.PBDNSMessage.INET:
            if msg.HasField('from'):
                ipfromstr = socket.inet_ntop(socket.AF_INET, fromvalue)
            if msg.HasField('to'):
                iptostr = socket.inet_ntop(socket.AF_INET, msg.to)
        else:
            if msg.HasField('from'):
                ipfromstr = socket.inet_ntop(socket.AF_INET6, fromvalue)
            if msg.HasField('to'):
                iptostr = socket.inet_ntop(socket.AF_INET6, msg.to)

        if msg.socketProtocol == dnsmessage_pb2.PBDNSMessage.UDP:
            protostr = 'UDP'
        else:
            protostr = 'TCP'

        messageidstr = binascii.hexlify(bytearray(msg.messageId))
        initialrequestidstr = ''
        if msg.HasField('initialRequestId'):
            initialrequestidstr = ', initial uuid: ' + binascii.hexlify(bytearray(msg.initialRequestId))

        requestorstr = ''
        requestor = self.getRequestorSubnet(msg)
        if requestor:
            requestorstr = ' (' + requestor + ')'

 
	if debug > 0:
        	print('%d   [%s] %s of size %d: %s%s -> %s (%s), id: %d, uuid: %s%s' % (
                                                                           thread_safe_counter.value(),
                                                                           datestr,
                                                                           typestr,
                                                                           msg.inBytes,
                                                                           ipfromstr,
                                                                           requestorstr,
                                                                           iptostr,
                                                                           protostr,
                                                                           msg.id,
                                                                           messageidstr,
                                                                           initialrequestidstr))

# ------------------------------------------------------------------------------
# extra fields - Seth 5/9/2017
# ------------------------------------------------------------------------------

	if debug > 0:
        	if msg.HasField('extraMsg'):
              		print('------> ExtraMsg...: %s' % msg.extraMsg)
        	if msg.HasField('extraVal'):
              		print('------> ExtraVal...: %d' % msg.extraVal)
              		strAns = {
                  	 	dnsmessage_pb2.PBDNSMessage.OTHER:   "other",
                   		dnsmessage_pb2.PBDNSMessage.BLKLST:  "blacklist",
                   		dnsmessage_pb2.PBDNSMessage.CACHE:   "cache",
                   		dnsmessage_pb2.PBDNSMessage.FORWARD: "forward",
              		}[msg.extraVal]
              		print('------> AnsFlag....: %s' % strAns)
        	extraFieldCount  = len(msg.extraFields)
        	print('------> ExtraFields: %d' % extraFieldCount)
        	for ii in msg.extraFields:
              		print('------> name: %s   iValue: %d   sValue: %s' % (ii.name, ii.iValue, ii.sValue))

# ------------------------------------------------------------------------------

    def getRequestorSubnet(self, msg):
        requestorstr = None
        if msg.HasField('originalRequestorSubnet'):
            if len(msg.originalRequestorSubnet) == 4:
                requestorstr = socket.inet_ntop(socket.AF_INET,
                                                msg.originalRequestorSubnet)
            elif len(msg.originalRequestorSubnet) == 16:
                requestorstr = socket.inet_ntop(socket.AF_INET6,
                                                msg.originalRequestorSubnet)
        return requestorstr

class PDNSPBListener(object):


    def __init__(self, addr, port):
        res = socket.getaddrinfo(addr, port, socket.AF_UNSPEC,
                                 socket.SOCK_STREAM, 0,
                                 socket.AI_PASSIVE)
        if len(res) != 1:
            print("Error parsing the supplied address")
            sys.exit(1)
        family, socktype, _, _, sockaddr = res[0]
        self._sock = socket.socket(family, socktype)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            self._sock.bind(sockaddr)
        except socket.error as exp:
            print("Error while binding: %s" % str(exp))
            sys.exit(1)

        self._sock.listen(100)

    def run(self):
        while True:
            (conn, _) = self._sock.accept()
            handler = PDNSPBConnHandler(conn)
            thread = threading.Thread(name='Connection Handler',
                                      target=PDNSPBConnHandler.run,
                                      args=[handler])
            thread.setDaemon(True)
            thread.start()

        self._sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit('Usage: %s <address> <port>' % (sys.argv[0]))

    PDNSPBListener(sys.argv[1], sys.argv[2]).run()
    sys.exit(0)
