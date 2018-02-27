echo "test dnsdist with rpz bad entry with the spoofing verification test"
echo "dig @127.0.0.1 -p 5200 ***SPOOF***1.2.3.4*1jw2mr4fmky.net"
echo ""
dig @127.0.0.1 -p 5200  ***SPOOF***1.2.3.4*1jw2mr4fmky.net
