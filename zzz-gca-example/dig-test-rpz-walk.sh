echo "test dnsdist with rpz bad entry that involve walking..... 12/10/2017"

echo "dig @127.0.0.1 -p 5200 1jw2mr4fmky.net"
echo ""
dig @127.0.0.1 -p 5200  1jw2mr4fmky.net

echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 z.1jw2mr4fmky.net"
echo ""
dig @127.0.0.1 -p 5200  z.1jw2mr4fmky.net

echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 yy.z.1jw2mr4fmky.net"
echo ""
dig @127.0.0.1 -p 5200  yy.z.1jw2mr4fmky.net

echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 xxx.yy.z.1jw2mr4fmky.net"
echo ""
dig @127.0.0.1 -p 5200  xxx.yy.z.1jw2mr4fmky.net

echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 wwww.xxx.yy.z.1jw2mr4fmky.net"
echo ""
dig @127.0.0.1 -p 5200  wwww.xxx.yy.z.1jw2mr4fmky.net


echo "*"
echo "-------------------------------------------------------------"
echo "*"

echo "dig @127.0.0.1 -p 5200 .wwww.xxx.yy.z.1jw2mr4fmky.net"
echo ""
dig @127.0.0.1 -p 5200  .wwww.xxx.yy.z.1jw2mr4fmky.net


echo "-------------------------------------------------------------"
