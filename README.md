# zerosocks

Simple `io_uring` SOCKS5 server with optional transparent TCP proxying for iptables `-j REDIRECT`.

## Running

```sh
cargo run --release -- 0.0.0.0:1080
```

The listener accepts plain SOCKS5 clients and Linux transparent redirect traffic on the same port. Redirected connections are detected via `SO_ORIGINAL_DST`.

## Configuration

- `ZEROSOCKS_DNS_SERVER`: DNS server for A-record lookups (default `1.1.1.1:53`).
- `ZEROSOCKS_IPMAP_<NAME>=FROM->TO`: rewrite destination IPs before dialing (applies to SOCKS and transparent). Use `*` as `FROM` for a wildcard match.
- `ZEROSOCKS_DENY_UNMAPPED=1`: reject connections that do not match any `ZEROSOCKS_IPMAP_*` rule.

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
