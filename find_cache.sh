#!/system/bin/sh
cd /data/data/com.hualai || exit 1
echo "=== files containing '3.13.212.24' ==="
grep -r -a -l '3\.13\.212\.24' . 2>/dev/null
echo "=== files containing '28800' ==="
grep -r -a -l '28800' . 2>/dev/null
echo "=== files containing 'srv' keys in xml ==="
grep -r -a -o -E 'name="[^"]*(p2p|P2P|relay|Relay|asrv|srv_)[^"]*"' shared_prefs/*.xml 2>/dev/null | sort -u | head -40
echo "=== any binary file with the raw IP 03 0d d4 18 ==="
for f in $(find . -type f -size -3M 2>/dev/null); do
  if grep -q -a -P '\x03\x0d\xd4\x18' "$f" 2>/dev/null; then echo "HIT: $f"; fi
done
echo "=== done ==="
