#!/bin/sh
# Filtering belongs to this VPN namespace; never flush or modify host chains.
# The raw hook runs before wg-easy's filter/NAT rules, including future rebuilds.
set -eu
umask 077
test -n "${VPN_ENDPOINT_IPV4:?Missing endpoint IPv4}"
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
# The pinned image defaults to legacy iptables. Use nft consistently for both
# wg-quick and our policy; no host modules or SYS_MODULE capability are needed.
mkdir -p /run/vpn-bin
ln -sf /usr/sbin/iptables-nft /run/vpn-bin/iptables
ln -sf /usr/sbin/ip6tables-nft /run/vpn-bin/ip6tables
export PATH="/run/vpn-bin:$PATH"
# A new network namespace starts with no monthly authorization. The trusted
# host controller must reserve durable budget before opening this own table.
if [ "${VPN_TRAFFIC_ENFORCE:-0}" = 1 ]; then
  old=''
  nft list table inet hermes_vpn_traffic >/dev/null 2>&1 && old='delete table inet hermes_vpn_traffic' || true
  nft -f - <<EOF
$old
table inet hermes_vpn_traffic {
  comment "closed"
  counter accepted {}
  counter rejected {}
  chain account { counter name "rejected" drop; }
  chain forward { type filter hook forward priority -10; policy accept; iifname "wg0" jump account; oifname "wg0" drop; }
  chain output { type filter hook output priority -10; policy accept; oifname "eth0" udp sport 51820 jump account; }
}
EOF
fi
fw=iptables-nft
$fw -w -t raw -N HERMES_VPN_PEERS 2>/dev/null || true
$fw -w -t raw -F HERMES_VPN_PEERS
# Rules match decapsulated packets on wg0 only. They never see the outer
# authenticated UDP transport.
for destination in \
  0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
  172.16.0.0/12 192.168.0.0/16 192.0.0.0/24 192.0.2.0/24 \
  198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 \
  "$VPN_ENDPOINT_IPV4/32" "${VPN_COBUDGET_IPV4:?Missing protected CoBudget IPv4}/32"; do
  $fw -w -t raw -A HERMES_VPN_PEERS -d "$destination" -j DROP
done
$fw -w -t raw -N HERMES_VPN_DNS 2>/dev/null || true
$fw -w -t raw -F HERMES_VPN_DNS
$fw -w -t raw -A HERMES_VPN_DNS -d 1.1.1.1/32 -j RETURN
$fw -w -t raw -A HERMES_VPN_DNS -d 1.0.0.1/32 -j RETURN
$fw -w -t raw -A HERMES_VPN_DNS -j DROP
$fw -w -t raw -A HERMES_VPN_PEERS -p udp --dport 53 -j HERMES_VPN_DNS
$fw -w -t raw -A HERMES_VPN_PEERS -p tcp --dport 53 -j HERMES_VPN_DNS
$fw -w -t raw -C PREROUTING -i wg0 -j HERMES_VPN_PEERS 2>/dev/null || \
  $fw -w -t raw -I PREROUTING 1 -i wg0 -j HERMES_VPN_PEERS
ip6tables-nft -w -t raw -N HERMES_VPN_IPV6 2>/dev/null || true
ip6tables-nft -w -t raw -F HERMES_VPN_IPV6
ip6tables-nft -w -t raw -A HERMES_VPN_IPV6 -j DROP
ip6tables-nft -w -t raw -C PREROUTING -i wg0 -j HERMES_VPN_IPV6 2>/dev/null || \
  ip6tables-nft -w -t raw -I PREROUTING 1 -i wg0 -j HERMES_VPN_IPV6
echo 'VPN namespace policy installed; private, host, metadata and peer destinations blocked.'
exec "$@"
