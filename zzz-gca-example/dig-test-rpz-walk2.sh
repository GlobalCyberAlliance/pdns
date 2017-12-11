echo "test dnsdist with rpz bad entry that involve walking..... 12/10/2017"

echo "dig @127.0.0.1 -p 5200 www.baidu.neteworks.com.moyan.cc"
echo ""
dig @127.0.0.1 -p 5200  www.baidu.neteworks.com.moyan.cc

echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 baidu.neteworks.com.moyan.cc"
echo ""
dig @127.0.0.1 -p 5200  baidu.neteworks.com.moyan.cc

echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 neteworks.com.moyan.cc"
echo ""
dig @127.0.0.1 -p 5200  neteworks.com.moyan.cc

echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 com.moyan.cc"
echo ""
dig @127.0.0.1 -p 5200  com.moyan.cc

echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 moyan.cc"
echo ""
dig @127.0.0.1 -p 5200  moyan.cc


echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 cc"
echo ""
dig @127.0.0.1 -p 5200  cc


echo "-------------------------------------------------------------"
