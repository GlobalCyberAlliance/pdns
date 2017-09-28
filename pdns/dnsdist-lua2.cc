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
#include "dnsdist-cache.hh"
#include "dnsrulactions.hh"
#include <thread>
#include "dolog.hh"
#include "sodcrypto.hh"
#include "base64.hh"
#include "lock.hh"
#include "gettime.hh"
#include <map>
#include <fstream>
#include <boost/logic/tribool.hpp>
#include "statnode.hh"
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dnsdist-lua.hh"

boost::tribool g_noLuaSideEffect;
static bool g_included{false};

/* this is a best effort way to prevent logging calls with no side-effects in the output of delta()
   Functions can declare setLuaNoSideEffect() and if nothing else does declare a side effect, or nothing
   has done so before on this invocation, this call won't be part of delta() output */
void setLuaNoSideEffect()
{
  if(g_noLuaSideEffect==false) // there has been a side effect already
    return;
  g_noLuaSideEffect=true;
}

void setLuaSideEffect()
{
  g_noLuaSideEffect=false;
}

bool getLuaNoSideEffect()
{
  return g_noLuaSideEffect==true;
}

void resetLuaSideEffect()
{
  g_noLuaSideEffect = boost::logic::indeterminate;
}

map<ComboAddress,int> filterScore(const map<ComboAddress, unsigned int,ComboAddress::addressOnlyLessThan >& counts, 
				  double delta, int rate)
{
  std::multimap<unsigned int,ComboAddress> score;
  for(const auto& e : counts) 
    score.insert({e.second, e.first});

  map<ComboAddress,int> ret;
  
  double lim = delta*rate;
  for(auto s = score.crbegin(); s != score.crend() && s->first > lim; ++s) {
    ret[s->second]=s->first;
  }
  return ret;
}


typedef std::function<void(const StatNode&, const StatNode::Stat&, const StatNode::Stat&)> statvisitor_t;

static void statNodeRespRing(statvisitor_t visitor, unsigned int seconds)
{
  struct timespec cutoff, now;
  gettime(&now);
  if (seconds) {
    cutoff = now;
    cutoff.tv_sec -= seconds;
  }

  std::lock_guard<std::mutex> lock(g_rings.respMutex);
  
  StatNode root;
  for(const auto& c : g_rings.respRing) {
    if (now < c.when)
      continue;

    if (seconds && c.when < cutoff)
      continue;

    root.submit(c.name, c.dh.rcode, c.requestor);
  }
  StatNode::Stat node;

  root.visit([&visitor](const StatNode* node_, const StatNode::Stat& self, const StatNode::Stat& children) {
      visitor(*node_, self, children);},  node);

}

vector<pair<unsigned int, std::unordered_map<string,string> > > getRespRing(boost::optional<int> rcode) 
{
  typedef std::unordered_map<string,string>  entry_t;
  vector<pair<unsigned int, entry_t > > ret;
  std::lock_guard<std::mutex> lock(g_rings.respMutex);
  
  entry_t e;
  unsigned int count=1;
  for(const auto& c : g_rings.respRing) {
    if(rcode && (rcode.get() != c.dh.rcode))
      continue;
    e["qname"]=c.name.toString();
    e["rcode"]=std::to_string(c.dh.rcode);
    ret.push_back(std::make_pair(count,e));
    count++;
  }
  return ret;
}

typedef   map<ComboAddress, unsigned int,ComboAddress::addressOnlyLessThan > counts_t;
map<ComboAddress,int> exceedRespGen(int rate, int seconds, std::function<void(counts_t&, const Rings::Response&)> T) 
{
  counts_t counts;
  struct timespec cutoff, mintime, now;
  gettime(&now);
  cutoff = mintime = now;
  cutoff.tv_sec -= seconds;

  std::lock_guard<std::mutex> lock(g_rings.respMutex);
  for(const auto& c : g_rings.respRing) {
    if(seconds && c.when < cutoff)
      continue;
    if(now < c.when)
      continue;

    T(counts, c);
    if(c.when < mintime)
      mintime = c.when;
  }
  double delta = seconds ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}

map<ComboAddress,int> exceedQueryGen(int rate, int seconds, std::function<void(counts_t&, const Rings::Query&)> T) 
{
  counts_t counts;
  struct timespec cutoff, mintime, now;
  gettime(&now);
  cutoff = mintime = now;
  cutoff.tv_sec -= seconds;

  ReadLock rl(&g_rings.queryLock);
  for(const auto& c : g_rings.queryRing) {
    if(seconds && c.when < cutoff)
      continue;
    if(now < c.when)
      continue;
    T(counts, c);
    if(c.when < mintime)
      mintime = c.when;
  }
  double delta = seconds ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}


map<ComboAddress,int> exceedRCode(int rate, int seconds, int rcode) 
{
  return exceedRespGen(rate, seconds, [rcode](counts_t& counts, const Rings::Response& r) 
		   {
		     if(r.dh.rcode == rcode)
		       counts[r.requestor]++;
		   });
}

map<ComboAddress,int> exceedRespByterate(int rate, int seconds) 
{
  return exceedRespGen(rate, seconds, [](counts_t& counts, const Rings::Response& r) 
		   {
		     counts[r.requestor]+=r.size;
		   });
}

#ifdef HAVE_DNSCRYPT
static bool generateDNSCryptCertificate(const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end, DnsCryptCert& certOut, DnsCryptPrivateKey& keyOut)
{
  bool success = false;
  unsigned char providerPrivateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
  sodium_mlock(providerPrivateKey, sizeof(providerPrivateKey));
  sodium_memzero(providerPrivateKey, sizeof(providerPrivateKey));

  try {
    ifstream providerKStream(providerPrivateKeyFile);
    providerKStream.read((char*) providerPrivateKey, sizeof(providerPrivateKey));
    if (providerKStream.fail()) {
      providerKStream.close();
      throw std::runtime_error("Invalid DNSCrypt provider key file " + providerPrivateKeyFile);
    }

    DnsCryptContext::generateCertificate(serial, begin, end, providerPrivateKey, keyOut, certOut);
    success = true;
  }
  catch(const std::exception& e) {
    errlog(e.what());
  }

  sodium_memzero(providerPrivateKey, sizeof(providerPrivateKey));
  sodium_munlock(providerPrivateKey, sizeof(providerPrivateKey));
  return success;
}
#endif /* HAVE_DNSCRYPT */

void moreLua(bool client)
{
  typedef NetmaskTree<DynBlock> nmts_t;
  g_lua.writeFunction("newCA", [](const std::string& name) { return ComboAddress(name); });

  g_lua.writeFunction("newNMG", []() { return NetmaskGroup(); });
  g_lua.registerFunction<void(NetmaskGroup::*)(const std::string&mask)>("addMask", [](NetmaskGroup&nmg, const std::string& mask)
                         {
                           nmg.addMask(mask);
                         });
  g_lua.registerFunction<void(NetmaskGroup::*)(const std::map<ComboAddress,int>& map)>("addMasks", [](NetmaskGroup&nmg, const std::map<ComboAddress,int>& map)
                         {
                           for (const auto& entry : map) {
                             nmg.addMask(Netmask(entry.first));
                           }
                         });

  g_lua.registerFunction("match", (bool (NetmaskGroup::*)(const ComboAddress&) const)&NetmaskGroup::match);
  g_lua.registerFunction("size", &NetmaskGroup::size);  
  g_lua.registerFunction("clear", &NetmaskGroup::clear);  


  g_lua.writeFunction("showDynBlocks", []() {
      setLuaNoSideEffect();
      auto slow = g_dynblockNMG.getCopy();
      struct timespec now;
      gettime(&now);
      boost::format fmt("%-24s %8d %8d %s\n");
      g_outputBuffer = (fmt % "What" % "Seconds" % "Blocks" % "Reason").str();
      for(const auto& e: slow) {
	if(now < e->second.until)
	  g_outputBuffer+= (fmt % e->first.toString() % (e->second.until.tv_sec - now.tv_sec) % e->second.blocks % e->second.reason).str();
      }
      auto slow2 = g_dynblockSMT.getCopy();
      slow2.visit([&now, &fmt](const SuffixMatchTree<DynBlock>& node) {
          if(now <node.d_value.until) {
            string dom("empty");
            if(!node.d_value.domain.empty())
              dom = node.d_value.domain.toString();
            g_outputBuffer+= (fmt % dom % (node.d_value.until.tv_sec - now.tv_sec) % node.d_value.blocks % node.d_value.reason).str();
          }
        });

    });

  g_lua.writeFunction("clearDynBlocks", []() {
      setLuaSideEffect();
      nmts_t nmg;
      g_dynblockNMG.setState(nmg);
      SuffixMatchTree<DynBlock> smt;
      g_dynblockSMT.setState(smt);
    });

  g_lua.writeFunction("addDynBlocks", 
                      [](const map<ComboAddress,int>& m, const std::string& msg, boost::optional<int> seconds, boost::optional<DNSAction::Action> action) { 
                           setLuaSideEffect();
			   auto slow = g_dynblockNMG.getCopy();
			   struct timespec until, now;
			   gettime(&now);
			   until=now;
                           int actualSeconds = seconds ? *seconds : 10;
			   until.tv_sec += actualSeconds; 
			   for(const auto& capair : m) {
			     unsigned int count = 0;
                             auto got = slow.lookup(Netmask(capair.first));
                             bool expired=false;
			     if(got) {
			       if(until < got->second.until) // had a longer policy
				 continue;
			       if(now < got->second.until) // only inherit count on fresh query we are extending
				 count=got->second.blocks;
                               else
                                 expired=true;
			     }
			     DynBlock db{msg,until,DNSName(),(action ? *action : DNSAction::Action::None)};
			     db.blocks=count;
                             if(!got || expired)
                               warnlog("Inserting dynamic block for %s for %d seconds: %s", capair.first.toString(), actualSeconds, msg);
			     slow.insert(Netmask(capair.first)).second=db;
			   }
			   g_dynblockNMG.setState(slow);
			 });

  g_lua.writeFunction("addDynBlockSMT", 
                      [](const vector<pair<unsigned int, string> >&names, const std::string& msg, boost::optional<int> seconds, boost::optional<DNSAction::Action> action) { 
                           setLuaSideEffect();
			   auto slow = g_dynblockSMT.getCopy();
			   struct timespec until, now;
			   gettime(&now);
			   until=now;
                           int actualSeconds = seconds ? *seconds : 10;
			   until.tv_sec += actualSeconds; 

 			   for(const auto& capair : names) {
			     unsigned int count = 0;
                             DNSName domain(capair.second);
                             auto got = slow.lookup(domain);
                             bool expired=false;
			     if(got) {
			       if(until < got->until) // had a longer policy
				 continue;
			       if(now < got->until) // only inherit count on fresh query we are extending
				 count=got->blocks;
                               else
                                 expired=true;
			     }

			     DynBlock db{msg,until,domain,(action ? *action : DNSAction::Action::None)};
			     db.blocks=count;
                             if(!got || expired)
                               warnlog("Inserting dynamic block for %s for %d seconds: %s", domain, actualSeconds, msg);
			     slow.add(domain, db);
			   }
			   g_dynblockSMT.setState(slow);
			 });

  g_lua.writeFunction("setDynBlocksAction", [](DNSAction::Action action) {
      if (!g_configurationDone) {
        if (action == DNSAction::Action::Drop || action == DNSAction::Action::Refused || action == DNSAction::Action::Truncate) {
          g_dynBlockAction = action;
        }
        else {
          errlog("Dynamic blocks action can only be Drop, Refused or Truncate!");
          g_outputBuffer="Dynamic blocks action can only be Drop, Refused or Truncate!\n";
        }
      } else {
        g_outputBuffer="Dynamic blocks action cannot be altered at runtime!\n";
      }
    });

  g_lua.registerFunction<bool(nmts_t::*)(const ComboAddress&)>("match", 
								     [](nmts_t& s, const ComboAddress& ca) { return s.match(ca); });

  g_lua.writeFunction("exceedServFails", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRCode(rate, seconds, RCode::ServFail);
    });
  g_lua.writeFunction("exceedNXDOMAINs", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRCode(rate, seconds, RCode::NXDomain);
    });



  g_lua.writeFunction("exceedRespByterate", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRespByterate(rate, seconds);
    });

  g_lua.writeFunction("exceedQTypeRate", [](uint16_t type, unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedQueryGen(rate, seconds, [type](counts_t& counts, const Rings::Query& q) {
	  if(q.qtype==type)
	    counts[q.requestor]++;
	});
    });

  g_lua.writeFunction("exceedQRate", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedQueryGen(rate, seconds, [](counts_t& counts, const Rings::Query& q) {
          counts[q.requestor]++;
	});
    });

  g_lua.writeFunction("getRespRing", getRespRing);

  g_lua.registerFunction<StatNode, unsigned int()>("numChildren", 
                                                      [](StatNode& sn) -> unsigned int {

                                                        return sn.children.size();
                                                      } );

  g_lua.registerMember("fullname", &StatNode::fullname);
  g_lua.registerMember("labelsCount", &StatNode::labelsCount);
  g_lua.registerMember("servfails", &StatNode::Stat::servfails);
  g_lua.registerMember("nxdomains", &StatNode::Stat::nxdomains);
  g_lua.registerMember("queries", &StatNode::Stat::queries);

  g_lua.writeFunction("statNodeRespRing", [](statvisitor_t visitor, boost::optional<unsigned int> seconds) {
      statNodeRespRing(visitor, seconds ? *seconds : 0);
    });

  g_lua.writeFunction("getTopBandwidth", [](unsigned int top) {
      setLuaNoSideEffect();
      return g_rings.getTopBandwidth(top);
    });
  g_lua.executeCode(R"(function topBandwidth(top) top = top or 10; for k,v in ipairs(getTopBandwidth(top)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");

  g_lua.writeFunction("delta", []() {
      setLuaNoSideEffect();
      // we hold the lua lock already!
      for(const auto& d : g_confDelta) {
        struct tm tm;
        localtime_r(&d.first.tv_sec, &tm);
        char date[80];
        strftime(date, sizeof(date)-1, "-- %a %b %d %Y %H:%M:%S %Z\n", &tm);
        g_outputBuffer += date;
        g_outputBuffer += d.second + "\n";
      }
    });

  g_lua.writeFunction("grepq", [](boost::variant<string, vector<pair<int,string> > > inp, boost::optional<unsigned int> limit) {
      setLuaNoSideEffect();
      boost::optional<Netmask>  nm;
      boost::optional<DNSName> dn;
      int msec=-1;

      vector<string> vec;
      auto str=boost::get<string>(&inp);
      if(str)
        vec.push_back(*str);
      else {
        auto v = boost::get<vector<pair<int, string> > >(inp);
        for(const auto& a: v) 
          vec.push_back(a.second);
      }
    
      for(const auto& s : vec) {
        try 
          {
            nm = Netmask(s);
          }
        catch(...) {
          if(boost::ends_with(s,"ms") && sscanf(s.c_str(), "%ums", &msec)) {
            ;
          }
          else {
            try { dn=DNSName(s); }
            catch(...) 
              {
                g_outputBuffer = "Could not parse '"+s+"' as domain name or netmask";
                return;
              }
          }
        }
      }

      decltype(g_rings.queryRing) qr;
      decltype(g_rings.respRing) rr;
      {
        ReadLock rl(&g_rings.queryLock);
        qr=g_rings.queryRing;
      }
      sort(qr.begin(), qr.end(), [](const decltype(qr)::value_type& a, const decltype(qr)::value_type& b) {
        return b.when < a.when;
      });
      {
	std::lock_guard<std::mutex> lock(g_rings.respMutex);
        rr=g_rings.respRing;
      }

      sort(rr.begin(), rr.end(), [](const decltype(rr)::value_type& a, const decltype(rr)::value_type& b) {
        return b.when < a.when;
      });
      
      unsigned int num=0;
      struct timespec now;
      gettime(&now);
            
      std::multimap<struct timespec, string> out;

      boost::format      fmt("%-7.1f %-47s %-12s %-5d %-25s %-5s %-6.1f %-2s %-2s %-2s %s\n");
      g_outputBuffer+= (fmt % "Time" % "Client" % "Server" % "ID" % "Name" % "Type" % "Lat." % "TC" % "RD" % "AA" % "Rcode").str();

      if(msec==-1) {
        for(const auto& c : qr) {
          bool nmmatch=true, dnmatch=true;
          if(nm)
            nmmatch = nm->match(c.requestor);
          if(dn)
            dnmatch = c.name.isPartOf(*dn);
          if(nmmatch && dnmatch) {
            QType qt(c.qtype);
            out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % "" % htons(c.dh.id) % c.name.toString() % qt.getName()  % "" % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") %  "Question").str() )) ;
            
            if(limit && *limit==++num)
              break;
          }
        }
      }
      num=0;


      string extra;
      for(const auto& c : rr) {
        bool nmmatch=true, dnmatch=true, msecmatch=true;
        if(nm)
          nmmatch = nm->match(c.requestor);
        if(dn)
          dnmatch = c.name.isPartOf(*dn);
        if(msec != -1)
          msecmatch=(c.usec/1000 > (unsigned int)msec);

        if(nmmatch && dnmatch && msecmatch) {
          QType qt(c.qtype);
	  if(!c.dh.rcode)
	    extra=". " +std::to_string(htons(c.dh.ancount))+ " answers";
	  else 
	    extra.clear();
          if(c.usec != std::numeric_limits<decltype(c.usec)>::max())
            out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % c.ds.toStringWithPort() % htons(c.dh.id) % c.name.toString()  % qt.getName()  % (c.usec/1000.0) % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") % (RCode::to_s(c.dh.rcode) + extra)).str()  )) ;
          else
            out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % c.ds.toStringWithPort() % htons(c.dh.id) % c.name.toString()  % qt.getName()  % "T.O" % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") % (RCode::to_s(c.dh.rcode) + extra)).str()  )) ;

          if(limit && *limit==++num)
            break;
        }
      }

      for(const auto& p : out) {
        g_outputBuffer+=p.second;
      }
    });

  g_lua.writeFunction("addDNSCryptBind", [](const std::string& addr, const std::string& providerName, const std::string& certFile, const std::string keyFile, boost::optional<localbind_t> vars) {
      if (g_configurationDone) {
        g_outputBuffer="addDNSCryptBind cannot be used at runtime!\n";
        return;
      }
#ifdef HAVE_DNSCRYPT
      bool doTCP = true;
      bool reusePort = false;
      int tcpFastOpenQueueSize = 0;
      std::string interface;

      parseLocalBindVars(vars, doTCP, reusePort, tcpFastOpenQueueSize, interface);

      try {
        DnsCryptContext ctx(providerName, certFile, keyFile);
        g_dnsCryptLocals.push_back(std::make_tuple(ComboAddress(addr, 443), ctx, reusePort, tcpFastOpenQueueSize, interface));
      }
      catch(std::exception& e) {
        errlog(e.what());
	g_outputBuffer="Error: "+string(e.what())+"\n";
      }
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

  g_lua.writeFunction("showDNSCryptBinds", []() {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
      ostringstream ret;
      boost::format fmt("%1$-3d %2% %|25t|%3$-20.20s %|26t|%4$-8d %|35t|%5$-21.21s %|56t|%6$-9d %|66t|%7$-21.21s" );
      ret << (fmt % "#" % "Address" % "Provider Name" % "Serial" % "Validity" % "P. Serial" % "P. Validity") << endl;
      size_t idx = 0;

      for (const auto& local : g_dnsCryptLocals) {
        const DnsCryptContext& ctx = std::get<1>(local);
        bool const hasOldCert = ctx.hasOldCertificate();
        const DnsCryptCert& cert = ctx.getCurrentCertificate();
        const DnsCryptCert& oldCert = ctx.getOldCertificate();

        ret<< (fmt % idx % std::get<0>(local).toStringWithPort() % ctx.getProviderName() % cert.signedData.serial % DnsCryptContext::certificateDateToStr(cert.signedData.tsEnd) % (hasOldCert ? oldCert.signedData.serial : 0) % (hasOldCert ? DnsCryptContext::certificateDateToStr(oldCert.signedData.tsEnd) : "-")) << endl;
        idx++;
      }

      g_outputBuffer=ret.str();
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

  g_lua.writeFunction("getDNSCryptBind", [client](size_t idx) {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
      DnsCryptContext* ret = nullptr;
      if (idx < g_dnsCryptLocals.size()) {
        ret = &(std::get<1>(g_dnsCryptLocals.at(idx)));
      }
      return ret;
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

#ifdef HAVE_DNSCRYPT
    /* DnsCryptContext bindings */
    g_lua.registerFunction<std::string(DnsCryptContext::*)()>("getProviderName", [](const DnsCryptContext& ctx) { return ctx.getProviderName(); });
    g_lua.registerFunction<DnsCryptCert(DnsCryptContext::*)()>("getCurrentCertificate", [](const DnsCryptContext& ctx) { return ctx.getCurrentCertificate(); });
    g_lua.registerFunction<DnsCryptCert(DnsCryptContext::*)()>("getOldCertificate", [](const DnsCryptContext& ctx) { return ctx.getOldCertificate(); });
    g_lua.registerFunction("hasOldCertificate", &DnsCryptContext::hasOldCertificate);
    g_lua.registerFunction("loadNewCertificate", &DnsCryptContext::loadNewCertificate);
    g_lua.registerFunction<void(DnsCryptContext::*)(const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end)>("generateAndLoadInMemoryCertificate", [](DnsCryptContext& ctx, const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end) {
        DnsCryptPrivateKey privateKey;
        DnsCryptCert cert;

        try {
          if (generateDNSCryptCertificate(providerPrivateKeyFile, serial, begin, end, cert, privateKey)) {
            ctx.setNewCertificate(cert, privateKey);
          }
        }
        catch(const std::exception& e) {
          errlog(e.what());
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }
    });

    /* DnsCryptCert */
    g_lua.registerFunction<std::string(DnsCryptCert::*)()>("getMagic", [](const DnsCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.magic), sizeof(cert.magic)); });
    g_lua.registerFunction<std::string(DnsCryptCert::*)()>("getEsVersion", [](const DnsCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.esVersion), sizeof(cert.esVersion)); });
    g_lua.registerFunction<std::string(DnsCryptCert::*)()>("getProtocolMinorVersion", [](const DnsCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.protocolMinorVersion), sizeof(cert.protocolMinorVersion)); });
    g_lua.registerFunction<std::string(DnsCryptCert::*)()>("getSignature", [](const DnsCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.signature), sizeof(cert.signature)); });
    g_lua.registerFunction<std::string(DnsCryptCert::*)()>("getResolverPublicKey", [](const DnsCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.signedData.resolverPK), sizeof(cert.signedData.resolverPK)); });
    g_lua.registerFunction<std::string(DnsCryptCert::*)()>("getClientMagic", [](const DnsCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.signedData.clientMagic), sizeof(cert.signedData.clientMagic)); });
    g_lua.registerFunction<uint32_t(DnsCryptCert::*)()>("getSerial", [](const DnsCryptCert& cert) { return cert.signedData.serial; });
    g_lua.registerFunction<uint32_t(DnsCryptCert::*)()>("getTSStart", [](const DnsCryptCert& cert) { return ntohl(cert.signedData.tsStart); });
    g_lua.registerFunction<uint32_t(DnsCryptCert::*)()>("getTSEnd", [](const DnsCryptCert& cert) { return ntohl(cert.signedData.tsEnd); });
#endif

    g_lua.writeFunction("generateDNSCryptProviderKeys", [](const std::string& publicKeyFile, const std::string privateKeyFile) {
        setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
        unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
        unsigned char privateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
        sodium_mlock(privateKey, sizeof(privateKey));

        try {
          DnsCryptContext::generateProviderKeys(publicKey, privateKey);

          ofstream pubKStream(publicKeyFile);
          pubKStream.write((char*) publicKey, sizeof(publicKey));
          pubKStream.close();

          ofstream privKStream(privateKeyFile);
          privKStream.write((char*) privateKey, sizeof(privateKey));
          privKStream.close();

          g_outputBuffer="Provider fingerprint is: " + DnsCryptContext::getProviderFingerprint(publicKey) + "\n";
        }
        catch(std::exception& e) {
          errlog(e.what());
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }

        sodium_memzero(privateKey, sizeof(privateKey));
        sodium_munlock(privateKey, sizeof(privateKey));
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

    g_lua.writeFunction("printDNSCryptProviderFingerprint", [](const std::string& publicKeyFile) {
        setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
        unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];

        try {
          ifstream file(publicKeyFile);
          file.read((char *) &publicKey, sizeof(publicKey));

          if (file.fail())
            throw std::runtime_error("Invalid dnscrypt provider public key file " + publicKeyFile);

          file.close();
          g_outputBuffer="Provider fingerprint is: " + DnsCryptContext::getProviderFingerprint(publicKey) + "\n";
        }
        catch(std::exception& e) {
          errlog(e.what());
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

    g_lua.writeFunction("generateDNSCryptCertificate", [](const std::string& providerPrivateKeyFile, const std::string& certificateFile, const std::string privateKeyFile, uint32_t serial, time_t begin, time_t end) {
        setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
        DnsCryptPrivateKey privateKey;
        DnsCryptCert cert;

        try {
          if (generateDNSCryptCertificate(providerPrivateKeyFile, serial, begin, end, cert, privateKey)) {
            privateKey.saveToFile(privateKeyFile);
            DnsCryptContext::saveCertFromFile(cert, certificateFile);
          }
        }
        catch(const std::exception& e) {
          errlog(e.what());
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

// ----------------------------------------------------------------------------
// Seth - GCA - named cache - 9/26/2017
// ----------------------------------------------------------------------------
// new lua functions - 9/26/2017
//
// NamedCacheX general methods:
//      addNamedCache(strCacheName) - create a named cache if it doesn't exist
//                        - example: addNamedCache("yyy")
//      swapNamedCaches(strCacheNameA, strCacheNameB) - swap the two named caches.
//                        - example: swapNamedCaches("xxx", "yyy")
//      showNamedCaches() - display list of named caches on terminal
//                        - example: showNamedCaches()
//
// NamedCacheX methods:
//      getNamedCache(strCacheName) - get named cache ptr, create if not exist
//                                  - example: ncx = getNamedCache("xxx")
//      init(strCacheType, strCacheMode, strFileName, maxEntries) - (re)initialize cache
//                         - examples:
//                              getNamedCache("xxx"):init("MAP", "ALL", strCDB,900000)
//                              getNamedCache("xxx"):init("LRU", "ALL", strCDB,10000)
//                           strCacheType - type of cache
//                                 "none" - no cache, always fails, used a minimal resource placeholder
//                                 "cdb"  - no cache, always read from cdb file
//                                 "lru"  - lru cache, use cdb file data
//                                 "map"  - load entire cdb file into memory map
//                           strCacheMode - cache mode (only used in lru mode at present)
//                                 "none" - don't store any entries found in cdb in cache.
//                                 "rpz"  - store rpz entries found in cdb file in cache.
//                                 "all"  - same as 'rpz', but also store 'not found in cdb'
//                                          entries in cache with zero length data field.
//                           strFileName  - path file name to cdb file
//                           maxEntries   - maximum entries in cache
//      getStats()         - get statistics in a table
//                         - example: tableStat2 = ncx:getStats()
//      showStats()        - directly print out statistics to terminal
//                         - example:  getNamedCache("xxx"):showStats()
//      resetCounters()    - reset statistic counters for the named cache
//                         - example:  getNamedCache("xxx"):resetCounters()
//      isFileOpen()       - return true if cdb file is OK
//                         - example:  print(getNamedCache("xxx"):isFileOpen())
//      getErrNum()        - return error message number (errno, from last i/o operation)
//                         - example: print(getNamedCache("xxx"):getErrNum())
//      getErrMsg()        - return error message text
//                         - example: print(getNamedCache("xxx"):getErrMsg())
//      lookupQuestTag()   - use DNSQuestion & addTag to store search results in QTag automatically
//                         - example: iResult = getNamedCache("xxx"):lookupQuestTag(dq)
//                           return integer with found status
//                               CACHE_HIT::HIT_NONE          - 0 (match not found)
//                               CACHE_HIT::HIT_CDB           - 1 (match found in cdb file, data field not empty)
//                               CACHE_HIT::HIT_CACHE         - 2 (match found in cache, data field not empty)
//                               CACHE_HIT::HIT_CACHE_NO_DATA - 3 (match found in cache, empty data field)
//                               CACHE_HIT::HIT_CDB_NO_DATA   - 4 (match found in cdb file, empty data field)
//                           DNSQuestion QTag fields:
//                               nc_found - text return status
//                                     0 length - match not found
//                                     "cdb"    - match found in cdb file, CACHE_HIT::HIT_CACHE || CACHE_HIT::HIT_CACHE_NO_DATA
//                                     "cache"  - match found in cache, CACHE_HIT::HIT_CACHE || CACHE_HIT::HIT_CACHE_NO_DATA
//                               nc_data - string from cdb table match
// ----------------------------------------------------------------------------

#ifdef HAVE_NAMEDCACHE


// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// NamedCacheX general methods
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// addNamedCache() - add a named cache, doesn't return pointer
//                 - example: addNamedCache("yyy")
// ----------------------------------------------------------------------------
  g_lua.writeFunction("addNamedCache", [](const std::string& cacheName) {
      setLuaSideEffect();
      auto localPools = g_namedCaches.getCopy();
      std::shared_ptr<NamedCacheX> pool = createNamedCacheIfNotExists(localPools, cacheName);
      g_namedCaches.setState(localPools);
    });

// ----------------------------------------------------------------------------
// swapNamedCaches() - swap between two named caches, doesn't return pointer
//                   - example: swapNamedCaches("xxx", "yyy")
// ----------------------------------------------------------------------------
  g_lua.writeFunction("swapNamedCaches", [](const std::string& cacheNameA, const std::string& cacheNameB) {
      setLuaSideEffect();
      auto localPools = g_namedCaches.getCopy();
      std::shared_ptr<NamedCacheX> entryCacheA = createNamedCacheIfNotExists(localPools, cacheNameA);
      std::shared_ptr<NamedCacheX> entryCacheB = createNamedCacheIfNotExists(localPools, cacheNameB);
      std::shared_ptr<DNSDistNamedCache> namedCacheTemp = entryCacheA->namedCache;
      entryCacheA->namedCache = entryCacheB->namedCache;
      entryCacheB->namedCache = namedCacheTemp;
      g_namedCaches.setState(localPools);
    });

// ----------------------------------------------------------------------------
// showNamedCaches() - show all the named caches
//                   - example: showNamedCaches()
// ----------------------------------------------------------------------------

    g_lua.writeFunction("showNamedCaches", []() {
      setLuaNoSideEffect();
      try {
        ostringstream ret;
        boost::format fmt("%1$8.8s %|5t|%2$4s %|5t|%3$4s %|5t|%4$4s %|5t|%5$8s %|5t|%6$8s %|5t|%7$12s %|5t|%8$12s %|5t|%9$12s %|5t|%10$12s %|5t|%11$12s %|5t|%12%");
        ret << (fmt % "Name" % "Type" % "Mode" % "Open" % "MaxCache" % "InCache" % "HitsCache" % "NoDataCache" % "CdbHits" % "CdbNoData"% " MissCache" % "FileName" ) << endl;
        ret << (fmt % "--------" % "----" % "----" % "----" % "--------" % "--------" % "------------" % "------------" % "------------" % "------------" % "------------" % "--------" ) << endl;

        const auto localNamedCaches = g_namedCaches.getCopy();
        for (const auto& entry : localNamedCaches) {
          const string& strCacheName = entry.first;                           // get name
          const std::shared_ptr<NamedCacheX> cacheEntry = entry.second;       // get object - was NamedCacheX
          string strFileName = cacheEntry->namedCache->getFileName();
          string strType = cacheEntry->namedCache->getCacheTypeText();
          string strMode = cacheEntry->namedCache->getCacheModeText();
          string strFileOpen = cacheEntry->namedCache->isFileOpen()?"Yes":"No";
          string strMaxEntries = std::to_string(cacheEntry->namedCache->getMaxEntries());
          string strInCache = std::to_string(cacheEntry->namedCache->getCacheEntries());
          string strHitsCache = std::to_string(cacheEntry->namedCache->getCacheHits());
          string strNoDataCache = std::to_string(cacheEntry->namedCache->getCacheHitsNoData());
          string strCdbHits = std::to_string(cacheEntry->namedCache->getCdbHits());
          string strCdbHitsNoData = std::to_string(cacheEntry->namedCache->getCdbHitsNoData());
          string strMissCache = std::to_string(cacheEntry->namedCache->getCacheMiss());
          ret << (fmt % strCacheName % strType % strMode % strFileOpen % strMaxEntries % strInCache % strHitsCache % strNoDataCache % strCdbHits % strCdbHitsNoData % strMissCache % strFileName) << endl;

        }
        g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// NamedCacheX methods
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// getNamedCache() - get ptr to named cache entry in table
//                   if it doesn't exist, create it.
//                 - example: ncx = getNamedCache("xxx")
// ----------------------------------------------------------------------------
    g_lua.writeFunction("getNamedCache", [client](const string& cacheName) {
        if (client) {
          printf("--------------> getNamedCache() - client exists!!!!! \n");
          return std::make_shared<NamedCacheX>();
        }
        auto localPools = g_namedCaches.getCopy();
        std::shared_ptr<NamedCacheX> cacheEntry = createNamedCacheIfNotExists(localPools, cacheName);
        g_namedCaches.setState(localPools);
        return cacheEntry;
      });

// ----------------------------------------------------------------------------
// init - (re)initialize a new cache
//      - examples:
//           getNamedCache("xxx"):init("MAP", "ALL", strCDB,900000)
//           getNamedCache("xxx"):init("LRU", "ALL", strCDB,10000)
// ----------------------------------------------------------------------------
    g_lua.registerFunction<bool(std::shared_ptr<NamedCacheX>::*)(const string&, const string&, const string&, size_t)>("init", [](const std::shared_ptr<NamedCacheX>pool, const string& strCacheType, const string& strCacheMode, const string& fileName, size_t maxEntries) {
        bool bStat = false;
        if (pool->namedCache) {
          std::shared_ptr<DNSDistNamedCache> nc = pool->namedCache;
          if (nc) {
            printf("DNSDistNamedCache::init() \n");
            bStat = nc->init(fileName, strCacheType, strCacheMode ,maxEntries, true);
            } else {
              printf("DNSDistNamedCache::init() - null ptr \n");
              }
        }
        return(bStat);
    });


// ----------------------------------------------------------------------------
// getStats - return statistics in a table
//          - example: tableStat2 = ncx:getStats()
// ----------------------------------------------------------------------------
    g_lua.registerFunction<std::unordered_map<string, string>(std::shared_ptr<NamedCacheX>::*)()>("getStats", [](const std::shared_ptr<NamedCacheX>pool) {
        std::unordered_map<string, string> tableResult;
        if (pool->namedCache) {
          std::shared_ptr<DNSDistNamedCache> nc = pool->namedCache;
          if (nc) {
            tableResult.insert({"file", nc->getFileName()});   // file used
            std::string strTemp = nc->isFileOpen()?"Yes":"No";
            tableResult.insert({"open", strTemp});             // file open
            tableResult.insert({"maxEntries", std::to_string(nc->getMaxEntries())});
            tableResult.insert({"cacheEntries", std::to_string(nc->getCacheEntries())});
            tableResult.insert({"cacheHits", std::to_string(nc->getCacheHits())});
            tableResult.insert({"cacheHitsNoData", std::to_string(nc->getCacheHitsNoData())});
            tableResult.insert({"cdbHits", std::to_string(nc->getCdbHits())});
            tableResult.insert({"cdbHitsNoData", std::to_string(nc->getCdbHitsNoData())});
            tableResult.insert({"cacheMiss", std::to_string(nc->getCacheMiss())});
            tableResult.insert({"errMsg", nc->getErrMsg()});
            tableResult.insert({"errNum", std::to_string(nc->getErrNum())});
            tableResult.insert({"objCount", std::to_string(nc.use_count())});
            tableResult.insert({"cacheMode", nc->getCacheModeText()});
            tableResult.insert({"cacheType", nc->getCacheTypeText()});

            time_t tTemp = nc->getCreationTime();
            struct tm* tm = localtime(&tTemp);
            char cTimeBuffer[30];
            strftime(cTimeBuffer, sizeof(cTimeBuffer), "%F %T %z", tm);
            cTimeBuffer[sizeof(cTimeBuffer)-1] = '\0';
            tableResult.insert({"creationTime", cTimeBuffer});

            tTemp = nc->getCounterResetTime();
            tm = localtime(&tTemp);
            strftime(cTimeBuffer, sizeof(cTimeBuffer), "%F %T %z", tm);
            cTimeBuffer[sizeof(cTimeBuffer)-1] = '\0';
            tableResult.insert({"counterResetTime", cTimeBuffer});
            }
        }
        return(tableResult);
    });

// ----------------------------------------------------------------------------
// showStats() - show statistics for named cache on terminal
//             - example:  getNamedCache("xxx"):showStats()
// ----------------------------------------------------------------------------

    g_lua.registerFunction<void(std::shared_ptr<NamedCacheX>::*)()>("showStats", [](const std::shared_ptr<NamedCacheX> pool) {

        if (pool->namedCache) {
          std::shared_ptr<DNSDistNamedCache> nc = pool->namedCache;
          printf("DNSDistNamedCache::debug() \n");
          printf("\tCache Type........: %s \n", nc->getCacheTypeText().c_str());
          printf("\tCache Mode........: %s \n", nc->getCacheModeText().c_str());

          time_t tTemp = nc->getCreationTime();
          struct tm* tm = localtime(&tTemp);
          char cTimeBuffer[30];
          strftime(cTimeBuffer, sizeof(cTimeBuffer), "%F %T %z", tm);
          cTimeBuffer[sizeof(cTimeBuffer)-1] = '\0';

          printf("\tCreation Time.....: %s \n", cTimeBuffer);
          printf("\tObject Count......: %lu \n", nc.use_count());
          std::string strTemp = nc->isFileOpen()?"Yes":"No";
          printf("\tCDB File..........: %s \n", nc->getFileName().c_str());
          printf("\tFile Opened.......: %s \n", strTemp.c_str());
          printf("\tError Number......: %d \n", nc->getErrNum());
          printf("\tError Message.....: %s \n", nc->getErrMsg().c_str());
          printf("\tMax Entries.......: %lu \n", nc->getMaxEntries());
          printf("\tIn Use Entries....: %lu \n", nc->getCacheEntries());

          tTemp = nc->getCounterResetTime();
          tm = localtime(&tTemp);
          strftime(cTimeBuffer, sizeof(cTimeBuffer), "%F %T %z", tm);
          cTimeBuffer[sizeof(cTimeBuffer)-1] = '\0';

          printf("\tCounter Reset Time: %s \n", cTimeBuffer);
          printf("\tCache Hits........: %lu \n", nc->getCacheHits());
          printf("\tCache Hits No Data: %lu \n", nc->getCacheHitsNoData());
          printf("\tCDB Hits..........: %lu \n", nc->getCdbHits());
          printf("\tCDB Hits No Data..: %lu \n", nc->getCdbHitsNoData());
          printf("\tCache Miss........: %lu \n", nc->getCacheMiss());
        } else {
          printf("DNSDistNamedCache::debug() - pointer is null! \n");
        }
      });

// ----------------------------------------------------------------------------
// resetCounters() - reset the counters for the named cache
//                 - example:  getNamedCache("xxx"):resetCounters()
// ----------------------------------------------------------------------------

    g_lua.registerFunction<void(std::shared_ptr<NamedCacheX>::*)()>("resetCounters", [](const std::shared_ptr<NamedCacheX> pool) {
        if (pool->namedCache) {
          std::shared_ptr<DNSDistNamedCache> nc = pool->namedCache;
          if (nc) {
            nc->resetCounters();
            }
          }
      });

// ----------------------------------------------------------------------------
// isFileOpen - return true if cdb file is OK
//            - example:  print(getNamedCache("xxx"):isFileOpen())
// ----------------------------------------------------------------------------

    g_lua.registerFunction<bool(std::shared_ptr<NamedCacheX>::*)()>("isFileOpen", [](const std::shared_ptr<NamedCacheX>pool) {
        if (pool->namedCache) {
          std::shared_ptr<DNSDistNamedCache> nc = pool->namedCache;
          if (nc) {
            return(nc->isFileOpen());
          }
        }
        return false;
      });

// ----------------------------------------------------------------------------
// getErrNum - return error message number (errno, from last i/o operation)
//           - example: print(getNamedCache("xxx"):getErrNum())
// ----------------------------------------------------------------------------

    g_lua.registerFunction<int(std::shared_ptr<NamedCacheX>::*)()>("getErrNum", [](const std::shared_ptr<NamedCacheX>pool) {
        if (pool->namedCache) {
          std::shared_ptr<DNSDistNamedCache> nc = pool->namedCache;
          if (nc) {
            return(nc->getErrNum());
          }
        }
        return 0;
      });

// ----------------------------------------------------------------------------
// getErrMsg - return error message text
//           - example: print(getNamedCache("xxx"):getErrMsg())
// ----------------------------------------------------------------------------

    g_lua.registerFunction<std::string(std::shared_ptr<NamedCacheX>::*)()>("getErrMsg", [](const std::shared_ptr<NamedCacheX>pool) {
        if (pool->namedCache) {
          std::shared_ptr<DNSDistNamedCache> nc = pool->namedCache;
          if (nc) {
            return(nc->getErrMsg());
          }
        }
        std::string strEmpty="";
        return strEmpty;
      });


// ----------------------------------------------------------------------------
// lookupQuestTag() - use DNSQuestion & addTag to store search results in QTag automatically
//                  - example: iResult = getNamedCache("xxx"):lookupQuestTag(dq)
//                  return integer with found status
//                               CACHE_HIT::HIT_NONE          - 0 (match not found)
//                               CACHE_HIT::HIT_CDB           - 1 (match found in cdb file, data field not empty)
//                               CACHE_HIT::HIT_CACHE         - 2 (match found in cache, data field not empty)
//                               CACHE_HIT::HIT_CACHE_NO_DATA - 3 (match found in cache, empty data field)
//                               CACHE_HIT::HIT_CDB_NO_DATA   - 4 (match found in cdb file, empty data field)
//                  DNSQuestion QTag fields:
//                      nc_found - text return status
//                              0 length - match not found
//                              "cdb"    - match found in cdb file, CACHE_HIT::HIT_CACHE || CACHE_HIT::HIT_CACHE_NO_DATA
//                              "cache"  - match found in cache, CACHE_HIT::HIT_CACHE || CACHE_HIT::HIT_CACHE_NO_DATA
//                      nc_data - string from cdb table match
// ----------------------------------------------------------------------------

    g_lua.registerFunction<int(std::shared_ptr<NamedCacheX>::*)(DNSQuestion *dq)>("lookupQuestTag", [](const std::shared_ptr<NamedCacheX> pool, DNSQuestion *dq) {
    int iGotIt = 0;
    if (pool->namedCache) {
      std::shared_ptr<DNSDistNamedCache> nc = pool->namedCache;

      std::string strQuery = toLower(dq->qname->toString());

      if(strQuery.back() == '.') {
        strQuery.pop_back();
        }

      std::string strRet;
      std::string strHit;
      iGotIt = nc->lookup(strQuery, strRet);
      switch(iGotIt) {
        case CACHE_HIT::HIT_CDB:
        case CACHE_HIT::HIT_CDB_NO_DATA:
          strHit = "cdb";
          break;
        case CACHE_HIT::HIT_CACHE:
        case CACHE_HIT::HIT_CACHE_NO_DATA:
          strHit = "cache";
          break;
        default:
          strHit = "";
          break;
        }

      if(dq->qTag == nullptr) {
        dq->qTag = std::make_shared<QTag>();
      }

     dq->qTag->add("nc_data", strRet);
     dq->qTag->add("nc_found", strHit);

    }
   return iGotIt;
   });

#endif

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

    g_lua.writeFunction("showPools", []() {
      setLuaNoSideEffect();
      try {
        ostringstream ret;
        boost::format fmt("%1$-20.20s %|25t|%2$20s %|25t|%3$20s %|50t|%4%" );
        //             1        2         3                4
        ret << (fmt % "Name" % "Cache" % "ServerPolicy" % "Servers" ) << endl;

        const auto localPools = g_pools.getCopy();
        for (const auto& entry : localPools) {
          const string& name = entry.first;
          const std::shared_ptr<ServerPool> pool = entry.second;
          string cache = pool->packetCache != nullptr ? pool->packetCache->toString() : "";
          string policy = g_policy.getLocal()->name;
          if (pool->policy != nullptr) {
            policy = pool->policy->name;
          }
          string servers;

          for (const auto& server: pool->servers) {
            if (!servers.empty()) {
              servers += ", ";
            }
            if (!server.second->name.empty()) {
              servers += server.second->name;
              servers += " ";
            }
            servers += server.second->remote.toStringWithPort();
          }

          ret << (fmt % name % cache % policy % servers) << endl;
        }
        g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

    g_lua.registerFunction<void(std::shared_ptr<ServerPool>::*)(std::shared_ptr<DNSDistPacketCache>)>("setCache", [](std::shared_ptr<ServerPool> pool, std::shared_ptr<DNSDistPacketCache> cache) {
        if (pool) {
          pool->packetCache = cache;
        }
    });
    g_lua.registerFunction("getCache", &ServerPool::getCache);
    g_lua.registerFunction<void(std::shared_ptr<ServerPool>::*)()>("unsetCache", [](std::shared_ptr<ServerPool> pool) {
        if (pool) {
          pool->packetCache = nullptr;
        }
    });

    g_lua.writeFunction("newPacketCache", [client](size_t maxEntries, boost::optional<uint32_t> maxTTL, boost::optional<uint32_t> minTTL, boost::optional<uint32_t> tempFailTTL, boost::optional<uint32_t> staleTTL, boost::optional<bool> dontAge) {
        return std::make_shared<DNSDistPacketCache>(maxEntries, maxTTL ? *maxTTL : 86400, minTTL ? *minTTL : 0, tempFailTTL ? *tempFailTTL : 60, staleTTL ? *staleTTL : 60, dontAge ? *dontAge : false);
      });
    g_lua.registerFunction("toString", &DNSDistPacketCache::toString);
    g_lua.registerFunction("isFull", &DNSDistPacketCache::isFull);
    g_lua.registerFunction("purgeExpired", &DNSDistPacketCache::purgeExpired);
    g_lua.registerFunction("expunge", &DNSDistPacketCache::expunge);
    g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)(const DNSName& dname, boost::optional<uint16_t> qtype, boost::optional<bool> suffixMatch)>("expungeByName", [](
                std::shared_ptr<DNSDistPacketCache> cache,
                const DNSName& dname,
                boost::optional<uint16_t> qtype,
                boost::optional<bool> suffixMatch) {
        if (cache) {
          cache->expungeByName(dname, qtype ? *qtype : QType::ANY, suffixMatch ? *suffixMatch : false);
        }
      });
    g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)()>("printStats", [](const std::shared_ptr<DNSDistPacketCache> cache) {
        if (cache) {
          g_outputBuffer="Entries: " + std::to_string(cache->getEntriesCount()) + "/" + std::to_string(cache->getMaxEntries()) + "\n";
          g_outputBuffer+="Hits: " + std::to_string(cache->getHits()) + "\n";
          g_outputBuffer+="Misses: " + std::to_string(cache->getMisses()) + "\n";
          g_outputBuffer+="Deferred inserts: " + std::to_string(cache->getDeferredInserts()) + "\n";
          g_outputBuffer+="Deferred lookups: " + std::to_string(cache->getDeferredLookups()) + "\n";
          g_outputBuffer+="Lookup Collisions: " + std::to_string(cache->getLookupCollisions()) + "\n";
          g_outputBuffer+="Insert Collisions: " + std::to_string(cache->getInsertCollisions()) + "\n";
          g_outputBuffer+="TTL Too Shorts: " + std::to_string(cache->getTTLTooShorts()) + "\n";
        }
      });

    g_lua.writeFunction("getPool", [client](const string& poolName) {
        if (client) {
          return std::make_shared<ServerPool>();
        }
        auto localPools = g_pools.getCopy();
        std::shared_ptr<ServerPool> pool = createPoolIfNotExists(localPools, poolName);
        g_pools.setState(localPools);
        return pool;
      });

    g_lua.writeFunction("setVerboseHealthChecks", [](bool verbose) { g_verboseHealthChecks=verbose; });
    g_lua.writeFunction("setStaleCacheEntriesTTL", [](uint32_t ttl) { g_staleCacheEntriesTTL = ttl; });

    g_lua.writeFunction("DropResponseAction", []() {
        return std::shared_ptr<DNSResponseAction>(new DropResponseAction);
      });

    g_lua.writeFunction("AllowResponseAction", []() {
        return std::shared_ptr<DNSResponseAction>(new AllowResponseAction);
      });

    g_lua.writeFunction("DelayResponseAction", [](int msec) {
        return std::shared_ptr<DNSResponseAction>(new DelayResponseAction(msec));
      });

    g_lua.writeFunction("RemoteLogAction", [](std::shared_ptr<RemoteLogger> logger, boost::optional<std::function<void(const DNSQuestion&, DNSDistProtoBufMessage*)> > alterFunc) {
#ifdef HAVE_PROTOBUF
        return std::shared_ptr<DNSAction>(new RemoteLogAction(logger, alterFunc));
#else
        throw std::runtime_error("Protobuf support is required to use RemoteLogAction");
#endif
      });
    g_lua.writeFunction("RemoteLogResponseAction", [](std::shared_ptr<RemoteLogger> logger, boost::optional<std::function<void(const DNSResponse&, DNSDistProtoBufMessage*)> > alterFunc, boost::optional<bool> includeCNAME) {
#ifdef HAVE_PROTOBUF
        return std::shared_ptr<DNSResponseAction>(new RemoteLogResponseAction(logger, alterFunc, includeCNAME ? *includeCNAME : false));
#else
        throw std::runtime_error("Protobuf support is required to use RemoteLogResponseAction");
#endif
      });

    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(std::string)>("setTag", [](DNSDistProtoBufMessage& message, const std::string& strValue) {
      message.addTag(strValue);
    });

    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(vector<pair<int, string>>)>("setTagArray", [](DNSDistProtoBufMessage& message, const vector<pair<int, string>>&tags) {
      for (const auto& tag : tags) {
        message.addTag(tag.second);
      }
    });

    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(boost::optional <time_t> sec, boost::optional <uint32_t> uSec)>("setProtobufResponseType",
                                        [](DNSDistProtoBufMessage& message, boost::optional <time_t> sec, boost::optional <uint32_t> uSec) {
      message.setType(DNSProtoBufMessage::Response);
      message.setQueryTime(sec?*sec:0, uSec?*uSec:0);
    });

    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string& strQueryName, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& strBlob)>("addResponseRR", [](DNSDistProtoBufMessage& message,
                                                            const std::string& strQueryName, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& strBlob) {
      message.addRR(DNSName(strQueryName), uType, uClass, uTTL, strBlob);
    });

    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const Netmask&)>("setEDNSSubnet", [](DNSDistProtoBufMessage& message, const Netmask& subnet) { message.setEDNSSubnet(subnet); });
    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const DNSName&, uint16_t, uint16_t)>("setQuestion", [](DNSDistProtoBufMessage& message, const DNSName& qname, uint16_t qtype, uint16_t qclass) { message.setQuestion(qname, qtype, qclass); });
    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(size_t)>("setBytes", [](DNSDistProtoBufMessage& message, size_t bytes) { message.setBytes(bytes); });
    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(time_t, uint32_t)>("setTime", [](DNSDistProtoBufMessage& message, time_t sec, uint32_t usec) { message.setTime(sec, usec); });
    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(time_t, uint32_t)>("setQueryTime", [](DNSDistProtoBufMessage& message, time_t sec, uint32_t usec) { message.setQueryTime(sec, usec); });
    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(uint8_t)>("setResponseCode", [](DNSDistProtoBufMessage& message, uint8_t rcode) { message.setResponseCode(rcode); });
    g_lua.registerFunction<std::string(DNSDistProtoBufMessage::*)()>("toDebugString", [](const DNSDistProtoBufMessage& message) { return message.toDebugString(); });

    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const ComboAddress&)>("setRequestor", [](DNSDistProtoBufMessage& message, const ComboAddress& addr) {
        message.setRequestor(addr);
      });
    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string&)>("setRequestorFromString", [](DNSDistProtoBufMessage& message, const std::string& str) {
        message.setRequestor(str);
      });
    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const ComboAddress&)>("setResponder", [](DNSDistProtoBufMessage& message, const ComboAddress& addr) {
        message.setResponder(addr);
      });
    g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string&)>("setResponderFromString", [](DNSDistProtoBufMessage& message, const std::string& str) {
        message.setResponder(str);
      });

    g_lua.writeFunction("newRemoteLogger", [client](const std::string& remote, boost::optional<uint16_t> timeout, boost::optional<uint64_t> maxQueuedEntries, boost::optional<uint8_t> reconnectWaitTime) {
        return std::make_shared<RemoteLogger>(ComboAddress(remote), timeout ? *timeout : 2, maxQueuedEntries ? *maxQueuedEntries : 100, reconnectWaitTime ? *reconnectWaitTime : 1);
      });

    g_lua.writeFunction("TeeAction", [](const std::string& remote, boost::optional<bool> addECS) {
        return std::shared_ptr<DNSAction>(new TeeAction(ComboAddress(remote, 53), addECS ? *addECS : false));
      });

    g_lua.writeFunction("ECSPrefixLengthAction", [](uint16_t v4PrefixLength, uint16_t v6PrefixLength) {
        return std::shared_ptr<DNSAction>(new ECSPrefixLengthAction(v4PrefixLength, v6PrefixLength));
      });

    g_lua.writeFunction("ECSOverrideAction", [](bool ecsOverride) {
        return std::shared_ptr<DNSAction>(new ECSOverrideAction(ecsOverride));
      });

    g_lua.writeFunction("DisableECSAction", []() {
        return std::shared_ptr<DNSAction>(new DisableECSAction());
      });

    g_lua.registerFunction<void(DNSAction::*)()>("printStats", [](const DNSAction& ta) {
        setLuaNoSideEffect();
        auto stats = ta.getStats();
        for(const auto& s : stats) {
          g_outputBuffer+=s.first+"\t";
          if((uint64_t)s.second == s.second)
            g_outputBuffer += std::to_string((uint64_t)s.second)+"\n";
          else
            g_outputBuffer += std::to_string(s.second)+"\n";
        }
      });

    g_lua.writeFunction("getAction", [](unsigned int num) {
        setLuaNoSideEffect();
        boost::optional<std::shared_ptr<DNSAction>> ret;
        auto rulactions = g_rulactions.getCopy();
        if(num < rulactions.size())
          ret=rulactions[num].second;
        return ret;
      });

    g_lua.registerFunction("getStats", &DNSAction::getStats);

    g_lua.writeFunction("addResponseAction", [](luadnsrule_t var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction> > era) {
        if (era.type() == typeid(std::shared_ptr<DNSAction>)) {
          throw std::runtime_error("addResponseAction() can only be called with response-related actions, not query-related ones. Are you looking for addAction()?");
        }

        auto ea = *boost::get<std::shared_ptr<DNSResponseAction>>(&era);

        setLuaSideEffect();
        auto rule=makeRule(var);
        g_resprulactions.modify([rule, ea](decltype(g_resprulactions)::value_type& rulactions){
            rulactions.push_back({rule, ea});
          });
      });

    g_lua.writeFunction("showResponseRules", []() {
        setLuaNoSideEffect();
        boost::format fmt("%-3d %9d %-50s %s\n");
        g_outputBuffer += (fmt % "#" % "Matches" % "Rule" % "Action").str();
        int num=0;
        for(const auto& lim : g_resprulactions.getCopy()) {
          string name = lim.first->toString();
          g_outputBuffer += (fmt % num % lim.first->d_matches % name % lim.second->toString()).str();
          ++num;
        }
      });

    g_lua.writeFunction("rmResponseRule", [](unsigned int num) {
        setLuaSideEffect();
        auto rules = g_resprulactions.getCopy();
        if(num >= rules.size()) {
          g_outputBuffer = "Error: attempt to delete non-existing rule\n";
          return;
        }
        rules.erase(rules.begin()+num);
        g_resprulactions.setState(rules);
      });

    g_lua.writeFunction("topResponseRule", []() {
        setLuaSideEffect();
        auto rules = g_resprulactions.getCopy();
        if(rules.empty())
          return;
        auto subject = *rules.rbegin();
        rules.erase(std::prev(rules.end()));
        rules.insert(rules.begin(), subject);
        g_resprulactions.setState(rules);
      });

    g_lua.writeFunction("mvResponseRule", [](unsigned int from, unsigned int to) {
        setLuaSideEffect();
        auto rules = g_resprulactions.getCopy();
        if(from >= rules.size() || to > rules.size()) {
          g_outputBuffer = "Error: attempt to move rules from/to invalid index\n";
          return;
        }
        auto subject = rules[from];
        rules.erase(rules.begin()+from);
        if(to == rules.size())
          rules.push_back(subject);
        else {
          if(from < to)
            --to;
          rules.insert(rules.begin()+to, subject);
        }
        g_resprulactions.setState(rules);
      });

    g_lua.writeFunction("addCacheHitResponseAction", [](luadnsrule_t var, std::shared_ptr<DNSResponseAction> ea) {
        setLuaSideEffect();
        auto rule=makeRule(var);
        g_cachehitresprulactions.modify([rule, ea](decltype(g_cachehitresprulactions)::value_type& rulactions){
            rulactions.push_back({rule, ea});
          });
      });

    g_lua.writeFunction("showCacheHitResponseRules", []() {
        setLuaNoSideEffect();
        boost::format fmt("%-3d %9d %-50s %s\n");
        g_outputBuffer += (fmt % "#" % "Matches" % "Rule" % "Action").str();
        int num=0;
        for(const auto& lim : g_cachehitresprulactions.getCopy()) {
          string name = lim.first->toString();
          g_outputBuffer += (fmt % num % lim.first->d_matches % name % lim.second->toString()).str();
          ++num;
        }
      });

    g_lua.writeFunction("rmCacheHitResponseRule", [](unsigned int num) {
        setLuaSideEffect();
        auto rules = g_cachehitresprulactions.getCopy();
        if(num >= rules.size()) {
          g_outputBuffer = "Error: attempt to delete non-existing rule\n";
          return;
        }
        rules.erase(rules.begin()+num);
        g_cachehitresprulactions.setState(rules);
      });

    g_lua.writeFunction("topCacheHitResponseRule", []() {
        setLuaSideEffect();
        auto rules = g_cachehitresprulactions.getCopy();
        if(rules.empty())
          return;
        auto subject = *rules.rbegin();
        rules.erase(std::prev(rules.end()));
        rules.insert(rules.begin(), subject);
        g_cachehitresprulactions.setState(rules);
      });

    g_lua.writeFunction("mvCacheHitResponseRule", [](unsigned int from, unsigned int to) {
        setLuaSideEffect();
        auto rules = g_cachehitresprulactions.getCopy();
        if(from >= rules.size() || to > rules.size()) {
          g_outputBuffer = "Error: attempt to move rules from/to invalid index\n";
          return;
        }
        auto subject = rules[from];
        rules.erase(rules.begin()+from);
        if(to == rules.size())
          rules.push_back(subject);
        else {
          if(from < to)
            --to;
          rules.insert(rules.begin()+to, subject);
        }
        g_cachehitresprulactions.setState(rules);
      });

    g_lua.writeFunction("showBinds", []() {
      setLuaNoSideEffect();
      try {
        ostringstream ret;
        boost::format fmt("%1$-3d %2$-20.20s %|25t|%3$-8.8s %|35t|%4%" );
        //             1    2           3            4
        ret << (fmt % "#" % "Address" % "Protocol" % "Queries" ) << endl;

        size_t counter = 0;
        for (const auto& front : g_frontends) {
          ret << (fmt % counter % front->local.toStringWithPort() % (front->udpFD != -1 ? "UDP" : "TCP") % front->queries) << endl;
          counter++;
        }
        g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

    g_lua.writeFunction("getBind", [](size_t num) {
        setLuaNoSideEffect();
        ClientState* ret = nullptr;
        if(num < g_frontends.size()) {
          ret=g_frontends[num];
        }
        return ret;
      });

    g_lua.registerFunction<std::string(ClientState::*)()>("toString", [](const ClientState& fe) {
        setLuaNoSideEffect();
        return fe.local.toStringWithPort();
      });

    g_lua.registerMember("muted", &ClientState::muted);

    g_lua.writeFunction("help", [](boost::optional<std::string> command) {
        setLuaNoSideEffect();
        g_outputBuffer = "";
        for (const auto& keyword : g_consoleKeywords) {
          if (!command) {
            g_outputBuffer += keyword.toString() + "\n";
          }
          else if (keyword.name == command) {
            g_outputBuffer = keyword.toString() + "\n";
            return;
          }
        }
        if (command) {
          g_outputBuffer = "Nothing found for " + *command + "\n";
        }
      });

    g_lua.writeFunction("showVersion", []() {
        setLuaNoSideEffect();
        g_outputBuffer = "dnsdist " + std::string(VERSION) + "\n";
      });

#ifdef HAVE_EBPF
    g_lua.writeFunction("newBPFFilter", [client](uint32_t maxV4, uint32_t maxV6, uint32_t maxQNames) {
        if (client) {
          return std::shared_ptr<BPFFilter>(nullptr);
        }
        return std::make_shared<BPFFilter>(maxV4, maxV6, maxQNames);
      });

    g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const ComboAddress& ca)>("block", [](std::shared_ptr<BPFFilter> bpf, const ComboAddress& ca) {
        if (bpf) {
          return bpf->block(ca);
        }
      });

    g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const DNSName& qname, boost::optional<uint16_t> qtype)>("blockQName", [](std::shared_ptr<BPFFilter> bpf, const DNSName& qname, boost::optional<uint16_t> qtype) {
        if (bpf) {
          return bpf->block(qname, qtype ? *qtype : 255);
        }
      });

    g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const ComboAddress& ca)>("unblock", [](std::shared_ptr<BPFFilter> bpf, const ComboAddress& ca) {
        if (bpf) {
          return bpf->unblock(ca);
        }
      });

    g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const DNSName& qname, boost::optional<uint16_t> qtype)>("unblockQName", [](std::shared_ptr<BPFFilter> bpf, const DNSName& qname, boost::optional<uint16_t> qtype) {
        if (bpf) {
          return bpf->unblock(qname, qtype ? *qtype : 255);
        }
      });

    g_lua.registerFunction<std::string(std::shared_ptr<BPFFilter>::*)()>("getStats", [](const std::shared_ptr<BPFFilter> bpf) {
        setLuaNoSideEffect();
        std::string res;
        if (bpf) {
          std::vector<std::pair<ComboAddress, uint64_t> > stats = bpf->getAddrStats();
          for (const auto& value : stats) {
            if (value.first.sin4.sin_family == AF_INET) {
              res += value.first.toString() + ": " + std::to_string(value.second) + "\n";
            }
            else if (value.first.sin4.sin_family == AF_INET6) {
              res += "[" + value.first.toString() + "]: " + std::to_string(value.second) + "\n";
            }
          }
          std::vector<std::tuple<DNSName, uint16_t, uint64_t> > qstats = bpf->getQNameStats();
          for (const auto& value : qstats) {
            res += std::get<0>(value).toString() + " " + std::to_string(std::get<1>(value)) + ": " + std::to_string(std::get<2>(value)) + "\n";
          }
        }
        return res;
      });

    g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)()>("attachToAllBinds", [](std::shared_ptr<BPFFilter> bpf) {
        std::string res;
        if (bpf) {
          for (const auto& frontend : g_frontends) {
            frontend->attachFilter(bpf);
          }
        }
      });

    g_lua.registerFunction<void(ClientState::*)()>("detachFilter", [](ClientState& frontend) {
        frontend.detachFilter();
    });

    g_lua.registerFunction<void(ClientState::*)(std::shared_ptr<BPFFilter>)>("attachFilter", [](ClientState& frontend, std::shared_ptr<BPFFilter> bpf) {
        if (bpf) {
          frontend.attachFilter(bpf);
        }
    });

    g_lua.writeFunction("setDefaultBPFFilter", [](std::shared_ptr<BPFFilter> bpf) {
        if (g_configurationDone) {
          g_outputBuffer="setDefaultBPFFilter() cannot be used at runtime!\n";
          return;
        }
        g_defaultBPFFilter = bpf;
      });

    g_lua.writeFunction("newDynBPFFilter", [client](std::shared_ptr<BPFFilter> bpf) {
        if (client) {
          return std::shared_ptr<DynBPFFilter>(nullptr);
        }
        return std::make_shared<DynBPFFilter>(bpf);
      });

    g_lua.writeFunction("registerDynBPFFilter", [](std::shared_ptr<DynBPFFilter> dbpf) {
        if (dbpf) {
          g_dynBPFFilters.push_back(dbpf);
        }
      });

    g_lua.writeFunction("unregisterDynBPFFilter", [](std::shared_ptr<DynBPFFilter> dbpf) {
        if (dbpf) {
          for (auto it = g_dynBPFFilters.begin(); it != g_dynBPFFilters.end(); it++) {
            if (*it == dbpf) {
              g_dynBPFFilters.erase(it);
              break;
            }
          }
        }
      });

    g_lua.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)(const ComboAddress& addr, boost::optional<int> seconds)>("block", [](std::shared_ptr<DynBPFFilter> dbpf, const ComboAddress& addr, boost::optional<int> seconds) {
        if (dbpf) {
          struct timespec until;
          clock_gettime(CLOCK_MONOTONIC, &until);
          until.tv_sec += seconds ? *seconds : 10;
          dbpf->block(addr, until);
        }
    });

    g_lua.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)()>("purgeExpired", [](std::shared_ptr<DynBPFFilter> dbpf) {
        if (dbpf) {
          struct timespec now;
          clock_gettime(CLOCK_MONOTONIC, &now);
          dbpf->purgeExpired(now);
        }
    });

    g_lua.writeFunction("addBPFFilterDynBlocks", [](const map<ComboAddress,int>& m, std::shared_ptr<DynBPFFilter> dynbpf, boost::optional<int> seconds) {
        setLuaSideEffect();
        struct timespec until, now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        until=now;
        int actualSeconds = seconds ? *seconds : 10;
        until.tv_sec += actualSeconds;
        for(const auto& capair : m) {
          dynbpf->block(capair.first, until);
        }
      });

#endif /* HAVE_EBPF */

    g_lua.writeFunction<std::unordered_map<string,uint64_t>()>("getStatisticsCounters", []() {
        setLuaNoSideEffect();
        std::unordered_map<string,uint64_t> res;
        for(const auto& entry : g_stats.entries) {
          if(const auto& val = boost::get<DNSDistStats::stat_t*>(&entry.second))
            res[entry.first] = (*val)->load();
        }
        return res;
      });

    g_lua.writeFunction("includeDirectory", [](const std::string& dirname) {
        if (g_configurationDone) {
          errlog("includeDirectory() cannot be used at runtime!");
          g_outputBuffer="includeDirectory() cannot be used at runtime!\n";
          return;
        }

        if (g_included) {
          errlog("includeDirectory() cannot be used recursively!");
          g_outputBuffer="includeDirectory() cannot be used recursively!\n";
          return;
        }

        g_included = true;
        struct stat st;

        if (stat(dirname.c_str(), &st)) {
          errlog("The included directory %s does not exist!", dirname.c_str());
          g_outputBuffer="The included directory " + dirname + " does not exist!";
          return;
        }

        if (!S_ISDIR(st.st_mode)) {
          errlog("The included directory %s is not a directory!", dirname.c_str());
          g_outputBuffer="The included directory " + dirname + " is not a directory!";
          return;
        }

        DIR *dirp;
        struct dirent *ent;
        std::list<std::string> files;
        if (!(dirp = opendir(dirname.c_str()))) {
          errlog("Error opening the included directory %s!", dirname.c_str());
          g_outputBuffer="Error opening the included directory " + dirname + "!";
          return;
        }

        while((ent = readdir(dirp)) != NULL) {
          if (ent->d_name[0] == '.') {
            continue;
          }

          if (boost::ends_with(ent->d_name, ".conf")) {
            std::ostringstream namebuf;
            namebuf << dirname.c_str() << "/" << ent->d_name;

            if (stat(namebuf.str().c_str(), &st) || !S_ISREG(st.st_mode)) {
              continue;
            }

            files.push_back(namebuf.str());
          }
        }

        closedir(dirp);
        files.sort();

        for (auto file = files.begin(); file != files.end(); ++file) {
          std::ifstream ifs(*file);
          if (!ifs) {
            warnlog("Unable to read configuration from '%s'", *file);
          } else {
            vinfolog("Read configuration from '%s'", *file);
          }

          g_lua.executeCode(ifs);
        }

        g_included = false;
    });

    g_lua.writeFunction("setAPIWritable", [](bool writable, boost::optional<std::string> apiConfigDir) {
        setLuaSideEffect();
        g_apiReadWrite = writable;
        if (apiConfigDir) {
          if (!(*apiConfigDir).empty()) {
            g_apiConfigDirectory = *apiConfigDir;
          }
          else {
            errlog("The API configuration directory value cannot be empty!");
            g_outputBuffer="The API configuration directory value cannot be empty!";
          }
        }
      });

    g_lua.writeFunction("setServFailWhenNoServer", [](bool servfail) {
        setLuaSideEffect();
        g_servFailOnNoPolicy = servfail;
      });

    g_lua.writeFunction("setRingBuffersSize", [](size_t capacity) {
        setLuaSideEffect();
        if (g_configurationDone) {
          errlog("setRingBuffersSize() cannot be used at runtime!");
          g_outputBuffer="setRingBuffersSize() cannot be used at runtime!\n";
          return;
        }
        g_rings.setCapacity(capacity);
      });

    g_lua.writeFunction("RDRule", []() {
      return std::shared_ptr<DNSRule>(new RDRule());
    });

    g_lua.writeFunction("TimedIPSetRule", []() {
      return std::shared_ptr<TimedIPSetRule>(new TimedIPSetRule());
    });

    g_lua.registerFunction<void(std::shared_ptr<TimedIPSetRule>::*)()>("clear", [](std::shared_ptr<TimedIPSetRule> tisr) {
        tisr->clear();
      });

    g_lua.registerFunction<void(std::shared_ptr<TimedIPSetRule>::*)()>("cleanup", [](std::shared_ptr<TimedIPSetRule> tisr) {
        tisr->cleanup();
      });

    g_lua.registerFunction<void(std::shared_ptr<TimedIPSetRule>::*)(const ComboAddress& ca, int t)>("add", [](std::shared_ptr<TimedIPSetRule> tisr, const ComboAddress& ca, int t) {
        tisr->add(ca, time(0)+t);
      });
        
    g_lua.registerFunction<std::shared_ptr<DNSRule>(std::shared_ptr<TimedIPSetRule>::*)()>("slice", [](std::shared_ptr<TimedIPSetRule> tisr) {
        return std::dynamic_pointer_cast<DNSRule>(tisr);
      });
    
    g_lua.writeFunction("setWHashedPertubation", [](uint32_t pertub) {
        setLuaSideEffect();
        g_hashperturb = pertub;
      });

    g_lua.writeFunction("setTCPUseSinglePipe", [](bool flag) {
        if (g_configurationDone) {
          g_outputBuffer="setTCPUseSinglePipe() cannot be used at runtime!\n";
          return;
        }
        setLuaSideEffect();
        g_useTCPSinglePipe = flag;
      });

    g_lua.writeFunction("snmpAgent", [](bool enableTraps, boost::optional<std::string> masterSocket) {
#ifdef HAVE_NET_SNMP
        if (g_configurationDone) {
          errlog("snmpAgent() cannot be used at runtime!");
          g_outputBuffer="snmpAgent() cannot be used at runtime!\n";
          return;
        }

        if (g_snmpEnabled) {
          errlog("snmpAgent() cannot be used twice!");
          g_outputBuffer="snmpAgent() cannot be used twice!\n";
          return;
        }

        g_snmpEnabled = true;
        g_snmpTrapsEnabled = enableTraps;
        g_snmpAgent = new DNSDistSNMPAgent("dnsdist", masterSocket ? *masterSocket : std::string());
#else
        errlog("NET SNMP support is required to use snmpAgent()");
        g_outputBuffer="NET SNMP support is required to use snmpAgent()\n";
#endif /* HAVE_NET_SNMP */
      });

    g_lua.writeFunction("SNMPTrapAction", [](boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
        return std::shared_ptr<DNSAction>(new SNMPTrapAction(reason ? *reason : ""));
#else
        throw std::runtime_error("NET SNMP support is required to use SNMPTrapAction()");
#endif /* HAVE_NET_SNMP */
      });

    g_lua.writeFunction("SNMPTrapResponseAction", [](boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
        return std::shared_ptr<DNSResponseAction>(new SNMPTrapResponseAction(reason ? *reason : ""));
#else
        throw std::runtime_error("NET SNMP support is required to use SNMPTrapResponseAction()");
#endif /* HAVE_NET_SNMP */
      });

    g_lua.writeFunction("sendCustomTrap", [](const std::string& str) {
#ifdef HAVE_NET_SNMP
        if (g_snmpAgent && g_snmpTrapsEnabled) {
          g_snmpAgent->sendCustomTrap(str);
        }
#endif /* HAVE_NET_SNMP */
      });

    g_lua.writeFunction("setPoolServerPolicy", [](ServerPolicy policy, string pool) {
        setLuaSideEffect();
        auto localPools = g_pools.getCopy();
        setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(policy));
        g_pools.setState(localPools);
      });

    g_lua.writeFunction("setPoolServerPolicyLua", [](string name, policyfunc_t policy, string pool) {
        setLuaSideEffect();
        auto localPools = g_pools.getCopy();
        setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(ServerPolicy{name, policy}));
        g_pools.setState(localPools);
      });

    g_lua.writeFunction("showPoolServerPolicy", [](string pool) {
        setLuaSideEffect();
        auto localPools = g_pools.getCopy();
        auto poolObj = getPool(localPools, pool);
        if (poolObj->policy == nullptr) {
          g_outputBuffer=g_policy.getLocal()->name+"\n";
        } else {
          g_outputBuffer=poolObj->policy->name+"\n";
        }
      });

    g_lua.writeFunction("setTCPDownstreamCleanupInterval", [](uint16_t interval) {
        setLuaSideEffect();
        g_downstreamTCPCleanupInterval = interval;
      });

    g_lua.writeFunction("setConsoleConnectionsLogging", [](bool enabled) {
        g_logConsoleConnections = enabled;
      });
}
