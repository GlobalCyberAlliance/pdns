echo "big test"
echo "here we go, takes a minute or so - 100,000 bad dns requests"

start=$(date +'%s')

for a in {1..100000}; do dig @127.0.0.1 -p 5200 +nocookie +noall 1jw2mr4fmky.net > /dev/null; done;

echo "It took $(($(date +'%s') - $start)) seconds"

echo "now type showServers() on command line for dnsdist"
