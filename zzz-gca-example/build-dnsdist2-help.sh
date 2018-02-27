#!/bin/bash -e
echo ""
echo "from:  http://dnsdist.org/download/"
echo ""
echo "clone from:  git clone https://github.com/PowerDNS/pdns.git"
echo "--or from our copy--"
echo "https://github.com/GlobalCyberAlliance/pdns.git"
echo ""

echo "cd ../pdns/dnsdistdist"
echo ""
cd ../pdns/dnsdistdist
echo ""
echo "autoreconf -i"
echo ""
autoreconf -i
echo ""
./configure --help


