/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "dnsdist.hh"
#include "dolog.hh"
#include "dnsparser.hh"
#include "dnsdist-cache.hh"

#include "dnsdist-gca-misc.hh"          // Seth - GCA - 4/14/2017

DNSDistPacketCache::DNSDistPacketCache(size_t maxEntries, uint32_t maxTTL, uint32_t minTTL, uint32_t tempFailureTTL, uint32_t staleTTL): d_maxEntries(maxEntries), d_maxTTL(maxTTL), d_tempFailureTTL(tempFailureTTL), d_minTTL(minTTL), d_staleTTL(staleTTL)
{
  pthread_rwlock_init(&d_lock, 0);
  /* we reserve maxEntries + 1 to avoid rehashing from occurring
     when we get to maxEntries, as it means a load factor of 1 */
  d_map.reserve(maxEntries + 1);
}

DNSDistPacketCache::~DNSDistPacketCache()
{
  try {
    WriteLock l(&d_lock);
  }
  catch(const PDNSException& pe) {
  }
}

bool DNSDistPacketCache::cachedValueMatches(const CacheValue& cachedValue, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool tcp)
{
  if (cachedValue.tcp != tcp || cachedValue.qtype != qtype || cachedValue.qclass != qclass || cachedValue.qname != qname)
    return false;
  return true;
}

void DNSDistPacketCache::insert(uint32_t key, const DNSName& qname, uint16_t qtype, uint16_t qclass, const char* response, uint16_t responseLen, bool tcp, uint8_t rcode)
{
  if (responseLen < sizeof(dnsheader))
    return;

  uint32_t minTTL;

  if (rcode == RCode::ServFail || rcode == RCode::Refused) {
    minTTL = d_tempFailureTTL;
    if (minTTL == 0) {
      return;
    }
  }
  else {
    minTTL = getMinTTL(response, responseLen);

    /* no TTL found, we don't want to cache this */
    if (minTTL == std::numeric_limits<uint32_t>::max()) {
      return;
    }

    if (minTTL > d_maxTTL) {
      minTTL = d_maxTTL;
    }

    if (minTTL < d_minTTL) {
      d_ttlTooShorts++;
      return;
    }
  }

  {
    TryReadLock r(&d_lock);
    if (!r.gotIt()) {
      d_deferredInserts++;
      return;
    }
    if (d_map.size() >= d_maxEntries) {
      return;
    }
  }

  const time_t now = time(NULL);
  std::unordered_map<uint32_t,CacheValue>::iterator it;
  bool result;
  time_t newValidity = now + minTTL;
  CacheValue newValue;
  newValue.qname = qname;
  newValue.qtype = qtype;
  newValue.qclass = qclass;
  newValue.len = responseLen;
  newValue.validity = newValidity;
  newValue.added = now;
  newValue.tcp = tcp;
  newValue.value = std::string(response, responseLen);

  {
    TryWriteLock w(&d_lock);

    if (!w.gotIt()) {
      d_deferredInserts++;
      return;
    }

    tie(it, result) = d_map.insert({key, newValue});

    if (result) {
      return;
    }

    /* in case of collision, don't override the existing entry
       except if it has expired */
    CacheValue& value = it->second;
    bool wasExpired = value.validity <= now;

    if (!wasExpired && !cachedValueMatches(value, qname, qtype, qclass, tcp)) {
      d_insertCollisions++;
      return;
    }

    /* if the existing entry had a longer TTD, keep it */
    if (newValidity <= value.validity) {
      return;
    }

    value = newValue;
  }
}

bool DNSDistPacketCache::get(const DNSQuestion& dq, uint16_t consumed, uint16_t queryId, char* response, uint16_t* responseLen, uint32_t* keyOut, uint32_t allowExpired, bool skipAging)
{
  uint32_t key = getKey(*dq.qname, consumed, (const unsigned char*)dq.dh, dq.len, dq.tcp);
  if (keyOut)
    *keyOut = key;

  time_t now = time(NULL);
  time_t age;
  bool stale = false;
  {
    TryReadLock r(&d_lock);
    if (!r.gotIt()) {
      d_deferredLookups++;
      return false;
    }

    std::unordered_map<uint32_t,CacheValue>::const_iterator it = d_map.find(key);
    if (it == d_map.end()) {
      d_misses++;
      return false;
    }

    const CacheValue& value = it->second;
    if (value.validity < now) {
      if ((now - value.validity) >= static_cast<time_t>(allowExpired)) {
        d_misses++;
        return false;
      }
      else {
        stale = true;
      }
    }

    if (*responseLen < value.len || value.len < sizeof(dnsheader)) {
      return false;
    }

    /* check for collision */
    if (!cachedValueMatches(value, *dq.qname, dq.qtype, dq.qclass, dq.tcp)) {
      d_lookupCollisions++;
      return false;
    }

    memcpy(response, &queryId, sizeof(queryId));
    memcpy(response + sizeof(queryId), value.value.c_str() + sizeof(queryId), sizeof(dnsheader) - sizeof(queryId));

    if (value.len == sizeof(dnsheader)) {
      /* DNS header only, our work here is done */
      *responseLen = value.len;
      d_hits++;
      return true;
    }

    string dnsQName(dq.qname->toDNSString());
    const size_t dnsQNameLen = dnsQName.length();
    if (value.len < (sizeof(dnsheader) + dnsQNameLen)) {
      return false;
    }

    memcpy(response + sizeof(dnsheader), dnsQName.c_str(), dnsQNameLen);
    if (value.len > (sizeof(dnsheader) + dnsQNameLen)) {
      memcpy(response + sizeof(dnsheader) + dnsQNameLen, value.value.c_str() + sizeof(dnsheader) + dnsQNameLen, value.len - (sizeof(dnsheader) + dnsQNameLen));
    }
    *responseLen = value.len;
    if (!stale) {
      age = now - value.added;
    }
    else {
      age = (value.validity - value.added) - d_staleTTL;
    }
  }

  if (!skipAging) {
    ageDNSPacket(response, *responseLen, age);
  }

  d_hits++;
  return true;
}

/* Remove expired entries, until the cache has at most
   upTo entries in it.
*/
void DNSDistPacketCache::purgeExpired(size_t upTo)
{
  time_t now = time(NULL);
  WriteLock w(&d_lock);
  if (upTo >= d_map.size()) {
    return;
  }

  size_t toRemove = d_map.size() - upTo;
  for(auto it = d_map.begin(); toRemove > 0 && it != d_map.end(); ) {
    const CacheValue& value = it->second;

    if (value.validity < now) {
        it = d_map.erase(it);
        --toRemove;
    } else {
      ++it;
    }
  }
}

/* Remove all entries, keeping only upTo
   entries in the cache */
void DNSDistPacketCache::expunge(size_t upTo)
{
  WriteLock w(&d_lock);

  if (upTo >= d_map.size()) {
    return;
  }

  size_t toRemove = d_map.size() - upTo;
  auto beginIt = d_map.begin();
  auto endIt = beginIt;
  std::advance(endIt, toRemove);
  d_map.erase(beginIt, endIt);
}

void DNSDistPacketCache::expungeByName(const DNSName& name, uint16_t qtype, bool suffixMatch)
{

  WriteLock w(&d_lock);

  for(auto it = d_map.begin(); it != d_map.end(); ) {
    const CacheValue& value = it->second;

    if ((value.qname == name || (suffixMatch && value.qname.isPartOf(name))) && (qtype == QType::ANY || qtype == value.qtype)) {
      it = d_map.erase(it);
    } else {
      ++it;
    }
  }
}

bool DNSDistPacketCache::isFull()
{
    ReadLock r(&d_lock);
    return (d_map.size() >= d_maxEntries);
}

uint32_t DNSDistPacketCache::getMinTTL(const char* packet, uint16_t length)
{
  return getDNSPacketMinTTL(packet, length);
}

uint32_t DNSDistPacketCache::getKey(const DNSName& qname, uint16_t consumed, const unsigned char* packet, uint16_t packetLen, bool tcp)
{
  uint32_t result = 0;
  /* skip the query ID */
  if (packetLen < sizeof(dnsheader))
    throw std::range_error("Computing packet cache key for an invalid packet size");
  result = burtle(packet + 2, sizeof(dnsheader) - 2, result);
  string lc(qname.toDNSStringLC());
  result = burtle((const unsigned char*) lc.c_str(), lc.length(), result);
  if (packetLen < sizeof(dnsheader) + consumed) {
    throw std::range_error("Computing packet cache key for an invalid packet");
  }
  if (packetLen > ((sizeof(dnsheader) + consumed))) {
    result = burtle(packet + sizeof(dnsheader) + consumed, packetLen - (sizeof(dnsheader) + consumed), result);
  }
  result = burtle((const unsigned char*) &tcp, sizeof(tcp), result);
  return result;
}

string DNSDistPacketCache::toString()
{
  ReadLock r(&d_lock);
  return std::to_string(d_map.size()) + "/" + std::to_string(d_maxEntries);
}

uint64_t DNSDistPacketCache::getEntriesCount()
{
  ReadLock r(&d_lock);
  return d_map.size();
}


//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
// Experimental Code
// Seth Ornstein
// Global Cyber Alliance
// 4/6/2017
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
// dumpCacheXXX() - dump the cache
//  			note: answer is in value.value
//  			note: value.getTTD() returns value.validity
//------------------------------------------------------------------------------
void DNSDistPacketCache::dumpCacheXXX()
{

  ReadLock r(&d_lock);				// lock for reading......

  printf("DNSDistPacketCache::dumpCache() - entries: %lu/%lu \n", d_map.size(), d_maxEntries);
  printf("              qname                qtype   qclass          added                validity          length   TYPE    EXTRA \n");
  printf("--------------------------------   -----   ------   -------------------    -------------------    ------   ----    ----- \n");

  char strTimeAdded[32];
  char strTimeValid[32];

  for(auto it = d_map.begin(); it != d_map.end(); ) {
    const CacheValue& value = it->second;
    strftime(strTimeAdded, 32, "%H:%M:%S %m-%d-%Y ", localtime(&value.added));
    strftime(strTimeValid, 32, "%H:%M:%S %m-%d-%Y ", localtime(&value.validity));
    printf("%32s   %5u   %6u   %19s   %19s   %6u   %4s   %5lu ",
			value.qname.toString().c_str(),
			value.qtype,
			value.qclass,
			strTimeAdded,
			strTimeValid,
			value.len,
			value.tcp?"TCP":"UDP",
			value.vecExtra.size()
 			);
    for(unsigned int ii=0; ii < value.vecExtra.size(); ii++)
       {
        printf("   %s - %s ", value.vecExtra[ii].strLabel.c_str(), value.vecExtra[ii].strValue.c_str());
       }
    printf("\n");
    ++it;
  }
  printf("DNSDistPacketCache::dumpCache() - finished. \n");
}

//------------------------------------------------------------------------------
// expungeByNameXXX() - expunge with debugging statements
//------------------------------------------------------------------------------
void DNSDistPacketCache::expungeByNameXXX(const DNSName& name, uint16_t qtype, bool suffixMatch)
{
  printf("DEBUG ---------------------------> DNSDistPacketCache::expungeByName - start \n");

  WriteLock w(&d_lock);

  for(auto it = d_map.begin(); it != d_map.end(); ) {
    const CacheValue& value = it->second;

    if ((value.qname == name || (suffixMatch && value.qname.isPartOf(name))) && (qtype == QType::ANY || qtype == value.qtype)) {
      printf("DEBUG ---------------------------> DNSDistPacketCache::expungeByName - gotit! \n");
      it = d_map.erase(it);
    } else {
      printf("DEBUG ---------------------------> DNSDistPacketCache::expungeByName - match: %s   value-name: %s   name: %s \n",
 						(value.qname == name)?"Yes":"No", value.qname.toString().c_str(), name.toString().c_str());
      ++it;
    }
  }
  printf("DEBUG ---------------------------> DNSDistPacketCache::expungeByName - end \n");
}



//------------------------------------------------------------------------------
// dumpAnswerXXX() - dump the dns answer from the cache
//------------------------------------------------------------------------------
int DNSDistPacketCache::dumpAnswerXXX(const std::string &value, uint16_t len)
{
int iStatus = 0;


    iStatus = DNSDistGcaMisc::dumpDNSAnswer(value, len);

    return(iStatus);
}

//------------------------------------------------------------------------------
// findByNameXXX() - find with debugging statements
//------------------------------------------------------------------------------
void DNSDistPacketCache::findByNameXXX(const DNSName& name, uint16_t qtype, bool suffixMatch)
{
int iHits = 0;

  printf("DNSDistPacketCache::findByNameXXX() - entries: %lu/%lu \n", d_map.size(), d_maxEntries);

//  WriteLock w(&d_lock);

  for(auto it = d_map.begin(); it != d_map.end(); ) {
    const CacheValue& value = it->second;

    if ((value.qname == name || (suffixMatch && value.qname.isPartOf(name))) && (qtype == QType::ANY || qtype == value.qtype)) {

      if(iHits == 0)
        {
         printf("              qname                qtype   qclass          added                validity          length   TYPE    EXTRA \n");
         printf("--------------------------------   -----   ------   -------------------    -------------------    ------   ----    ----- \n");
        }

      char strTimeAdded[32];
      char strTimeValid[32];

      const CacheValue& value = it->second;
      strftime(strTimeAdded, 32, "%H:%M:%S %m-%d-%Y ", localtime(&value.added));
      strftime(strTimeValid, 32, "%H:%M:%S %m-%d-%Y ", localtime(&value.validity));
      printf("%32s   %5u   %6u   %19s   %19s   %6u   %4s   %5lu ",
			value.qname.toString().c_str(),
			value.qtype,
			value.qclass,
			strTimeAdded,
			strTimeValid,
			value.len,
			value.tcp?"TCP":"UDP",
			value.vecExtra.size()
 			);
      for(unsigned int ii=0; ii < value.vecExtra.size(); ii++)
         {
          printf("   %s - %s ", value.vecExtra[ii].strLabel.c_str(), value.vecExtra[ii].strValue.c_str());
         }
      printf(" strlen-> %lu ", value.value.length());          // length of string
      printf("\n");



      printf("Try and resolve the answer.... \n");
      printf("Code borrowed from:  http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/ \n");

      dumpAnswerXXX(value.value, value.len);                    // dump the answer


      iHits++;                                                  // hit counter


    } else {
/*
      printf("DNSDistPacketCache::findByNameXXX() - NOT_match: %s   value-name: %s   name: %s \n",
 						(value.qname == name)?"Yes":"No", value.qname.toString().c_str(), name.toString().c_str());
*/
    }
   ++it;
  }
  printf("DNSDistPacketCache::findByNameXXX() - Hits: %d \n", iHits);
}



//------------------------------------------------------------------------------
// getXXX() -
//------------------------------------------------------------------------------
bool DNSDistPacketCache::getXXX(const DNSQuestion& dq, uint16_t consumed, uint16_t queryId, char* response, uint16_t* responseLen, uint32_t* keyOut, uint32_t allowExpired, bool skipAging)
{

printf("DEBUG ---------------------------> DNSDistPacketCache::getXXX - start \n");

  uint32_t key = getKey(*dq.qname, consumed, (const unsigned char*)dq.dh, dq.len, dq.tcp);
  if (keyOut)
    *keyOut = key;

  time_t now = time(NULL);
  time_t age;
  bool stale = false;
  {
    TryReadLock r(&d_lock);
    if (!r.gotIt()) {
      d_deferredLookups++;

  printf("DEBUG ---------------------------> DNSDistPacketCache::getXXX - false - no read lock \n");

      return false;
    }

    std::unordered_map<uint32_t,CacheValue>::const_iterator it = d_map.find(key);
    if (it == d_map.end()) {
      d_misses++;

  printf("DEBUG ---------------------------> DNSDistPacketCache::getXXX - false - got to end \n");

      return false;
    }

    const CacheValue& value = it->second;
    if (value.validity < now) {
      if ((now - value.validity) >= static_cast<time_t>(allowExpired)) {
        d_misses++;

  printf("DEBUG ---------------------------> DNSDistPacketCache::getXXX - false - not valid anymore \n");


        return false;
      }
      else {
        stale = true;
      }
    }

    if (*responseLen < value.len || value.len < sizeof(dnsheader)) {

      printf("DEBUG ---------------------------> DNSDistPacketCache::getXXX - false - response too short \n");

      return false;
    }

    /* check for collision */
    if (!cachedValueMatches(value, *dq.qname, dq.qtype, dq.qclass, dq.tcp)) {
      d_lookupCollisions++;

        printf("DEBUG ---------------------------> DNSDistPacketCache::getXXX - false - collisions \n");

      return false;
    }

    memcpy(response, &queryId, sizeof(queryId));
    memcpy(response + sizeof(queryId), value.value.c_str() + sizeof(queryId), sizeof(dnsheader) - sizeof(queryId));

    if (value.len == sizeof(dnsheader)) {
      /* DNS header only, our work here is done */
      *responseLen = value.len;
      d_hits++;

  printf("DEBUG ---------------------------> DNSDistPacketCache::getXXX - true - DNS header only \n");

      return true;
    }

    string dnsQName(dq.qname->toDNSString());
    const size_t dnsQNameLen = dnsQName.length();
    if (value.len < (sizeof(dnsheader) + dnsQNameLen)) {

      printf("DEBUG ---------------------------> DNSDistPacketCache::getXXX - false - length too short #2 \n");

      return false;
    }

    memcpy(response + sizeof(dnsheader), dnsQName.c_str(), dnsQNameLen);
    if (value.len > (sizeof(dnsheader) + dnsQNameLen)) {
      memcpy(response + sizeof(dnsheader) + dnsQNameLen, value.value.c_str() + sizeof(dnsheader) + dnsQNameLen, value.len - (sizeof(dnsheader) + dnsQNameLen));
    }
    *responseLen = value.len;
    if (!stale) {
      age = now - value.added;
    }
    else {
      age = (value.validity - value.added) - d_staleTTL;
    }
  }

  if (!skipAging) {
    ageDNSPacket(response, *responseLen, age);
  }

  d_hits++;

  printf("DEBUG ---------------------------> DNSDistPacketCache::getXXX - end - true \n");

  return true;

}

//------------------------------------------------------------------------------
// insertEntryXXX() - insertEntry into cache
//------------------------------------------------------------------------------
void DNSDistPacketCache::insertEntryXXX(const DNSName& name, uint16_t qtype, bool suffixMatch)
{
  printf("DEBUG ---------------------------> DNSDistPacketCache::insertEntryXXX - start \n");


      DNSName a=name;
      ComboAddress remote;
      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      vector<uint8_t> response;
      DNSPacketWriter pwR(response, a, QType::A, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(a, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();
      uint16_t responseLen = response.size();

      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, (struct dnsheader*) query.data(), query.size(), query.size(), false);
      bool bFound = getXXX(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key);

  printf("DEBUG ---------------------------> DNSDistPacketCache::insertEntryXXX - Found in cache before insert: %s \n", bFound?"Yes":"No");


      std::vector<CacheValueExtra> vecExtras;

      int ii = 1;
      struct CacheValueExtra evTemp;
      std::stringstream ss;
      ss << "test " << ii;
      evTemp.strLabel = ss.str();
      ss.str("");
      ss << "val " << ii;
      evTemp.strValue = ss.str();
      vecExtras.push_back(evTemp);


      insertXXX(key, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, 0, vecExtras);

  printf("DEBUG ---------------------------> DNSDistPacketCache::insertEntryXXX - end \n");
}

//------------------------------------------------------------------------------
void DNSDistPacketCache::insertXXX(uint32_t key, const DNSName& qname, uint16_t qtype, uint16_t qclass, const char* response, uint16_t responseLen, bool tcp, uint8_t rcode, std::vector<CacheValueExtra> &vecExtras)
{
  if (responseLen < sizeof(dnsheader))
    return;

  uint32_t minTTL;

  if (rcode == RCode::ServFail || rcode == RCode::Refused) {
    minTTL = d_tempFailureTTL;
    if (minTTL == 0) {
      return;
    }
  }
  else {
    minTTL = getMinTTL(response, responseLen);

    /* no TTL found, we don't want to cache this */
    if (minTTL == std::numeric_limits<uint32_t>::max()) {
      return;
    }

    if (minTTL > d_maxTTL) {
      minTTL = d_maxTTL;
    }

    if (minTTL < d_minTTL) {
      d_ttlTooShorts++;
      return;
    }
  }

  {
    TryReadLock r(&d_lock);
    if (!r.gotIt()) {
      d_deferredInserts++;
      return;
    }
    if (d_map.size() >= d_maxEntries) {
      return;
    }
  }

  const time_t now = time(NULL);
  std::unordered_map<uint32_t,CacheValue>::iterator it;
  bool result;
  time_t newValidity = now + minTTL;
  CacheValue newValue;
  newValue.qname = qname;
  newValue.qtype = qtype;
  newValue.qclass = qclass;
  newValue.len = responseLen;
  newValue.validity = newValidity;
  newValue.added = now;
  newValue.tcp = tcp;
  newValue.value = std::string(response, responseLen);

  newValue.vecExtra = vecExtras;                   // copy extra vectors in - Seth 4/7/2017

  {
    TryWriteLock w(&d_lock);

    if (!w.gotIt()) {
      d_deferredInserts++;
      return;
    }

    tie(it, result) = d_map.insert({key, newValue});

    if (result) {
      return;
    }

    /* in case of collision, don't override the existing entry
       except if it has expired */
    CacheValue& value = it->second;
    bool wasExpired = value.validity <= now;

    if (!wasExpired && !cachedValueMatches(value, qname, qtype, qclass, tcp)) {
      d_insertCollisions++;
      return;
    }

    /* if the existing entry had a longer TTD, keep it */
    if (newValidity <= value.validity) {
      return;
    }

    value = newValue;
  }
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
