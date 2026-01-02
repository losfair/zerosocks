# zerosocks

Simple `io_uring` SOCKS5 server with optional transparent TCP proxying for iptables `-j REDIRECT` or `-j TPROXY`.

## Running

```sh
cargo run --release -- 0.0.0.0:1080
```

To enter another process' network namespace for outbound connections (after binding the listener):

```sh
ZEROSOCKS_NETNS_PID=1234 cargo run --release -- 0.0.0.0:1080
```

The listener accepts plain SOCKS5 clients and Linux transparent redirect traffic on the same port. Redirected connections are detected via `SO_ORIGINAL_DST`. In TPROXY mode (`ZEROSOCKS_TPROXY=1`), the listener uses `IP_TRANSPARENT` and only handles redirected traffic (no SOCKS5 handshake).

## Configuration

- `ZEROSOCKS_DNS_SERVER`: DNS server for A-record lookups (default `1.1.1.1:53`).
- `ZEROSOCKS_IPMAP_<NAME>=FROM->TO`: rewrite destination IPs before dialing (applies to SOCKS and transparent). Use `*` as `FROM` for a wildcard match.
- `ZEROSOCKS_DENY_UNMAPPED=1`: reject connections that do not match any `ZEROSOCKS_IPMAP_*` rule.
- `ZEROSOCKS_TPROXY=1`: bind with `IP_TRANSPARENT` and expect `-j TPROXY` traffic (Linux only). Disables SOCKS5 serving.
- `ZEROSOCKS_FWMARK`: set `SO_MARK` on outbound sockets (accepts decimal or `0x` hex values).

Example that rewrites one host and blocks anything else:

```sh
ZEROSOCKS_IPMAP_DB=203.0.113.10->10.0.0.10 \
ZEROSOCKS_DENY_UNMAPPED=1 \
cargo run --release -- 0.0.0.0:1080
```

## Using iptables REDIRECT

Transparent mode requires Linux with a kernel that supports `SO_ORIGINAL_DST` (most distributions). Redirect only the traffic you need and exclude the proxy process itself to avoid loops.

### Redirect local outbound traffic

```sh
# allow redirecting back to loopback
sudo sysctl -w net.ipv4.conf.lo.route_localnet=1

PORT=1080
uid=$(id -u zerosocks)    # or the uid running the proxy

# Redirect TCP traffic to the proxy, excluding the proxy's own connections.
sudo iptables -t nat -A OUTPUT -p tcp \
  ! -d 127.0.0.1 \
  -m owner ! --uid-owner "$uid" \
  -j REDIRECT --to-ports "$PORT"
```

For IPv6 traffic, repeat the rule with `ip6tables` and `--to-ports "$PORT"`.

### Redirect traffic on a gateway

On a router handling traffic for other hosts, place the rule in `PREROUTING` instead:

```sh
sudo iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports 1080
```

Adjust interfaces, destination ports, or address matches to fit your environment.

## Using iptables TPROXY

Enable `ZEROSOCKS_TPROXY=1` and run zerosocks as a user with `CAP_NET_ADMIN` (or root) so it can set `IP_TRANSPARENT` and bind non-local addresses.

### Example (IPv4)

```sh
PORT=1080
sudo sysctl -w net.ipv4.conf.all.route_localnet=1

# Mark packets and route them to the local table.
sudo iptables -t mangle -A PREROUTING -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port "$PORT"
sudo ip rule add fwmark 0x1/0x1 table 100
sudo ip route add local 0.0.0.0/0 dev lo table 100

ZEROSOCKS_TPROXY=1 cargo run --release -- 0.0.0.0:$PORT
```

Adjust marks, tables, and interfaces as needed. The TPROXY listener does not speak SOCKS; it only forwards transparently.
