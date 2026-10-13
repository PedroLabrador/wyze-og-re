#!/system/bin/sh
echo "=== /proc/net/tcp (all LAN peers) ==="
grep -h -i -E 'D90000C0|E00000C0|A90000C0|750000C0' /proc/net/tcp 2>/dev/null
echo "=== /proc/net/tcp6 ==="
grep -h -i -E 'D90000C0|E00000C0|A90000C0|750000C0' /proc/net/tcp6 2>/dev/null
echo "=== /proc/net/udp ==="
grep -h -i -E 'D90000C0|E00000C0|A90000C0|750000C0' /proc/net/udp 2>/dev/null
echo "=== /proc/net/udp6 ==="
grep -h -i -E 'D90000C0|E00000C0|A90000C0|750000C0' /proc/net/udp6 2>/dev/null
echo "=== headers ==="
head -1 /proc/net/tcp; head -1 /proc/net/udp
echo "=== end ==="
