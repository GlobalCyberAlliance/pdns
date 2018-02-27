echo "grep multiple periods in keys - 12-11-2017"

./dumpKeys.sh > keys.txt

grep -E '(.*\.){4}' keys.txt

rm keys.txt



