echo "test dnsdist with 5 questions......"
echo "dig @127.0.0.1 -p 5200 +nocookie yahoo.com"
echo ""
dig @127.0.0.1 -p 5200 +nocookie yahoo.com
dig @127.0.0.1 -p 5200 +nocookie yahooxxx.com
dig @127.0.0.1 -p 5200 +nocookie google.com
dig @127.0.0.1 -p 5200 +nocookie nytimes.com
dig @127.0.0.1 -p 5200 +nocookie washpost.com
