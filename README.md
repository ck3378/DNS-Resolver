# DNS Resolver

A dependency-free Python 3 iterative DNS resolver using UDP over IPv4. It starts
at a hardcoded list of root-server addresses, follows referrals and in-bailiwick
IPv4 glue, and looks up out-of-bailiwick nameserver addresses iteratively.
Successful answers are cached by question until the shortest answer TTL expires.
The resolver forwards the requested type and class unchanged and includes a
zero-length EDNS(0) OPT record in upstream queries.

## Run

```sh
python3 resolver.py [port]
```

The default port is 53. The process binds to `0.0.0.0`; run it only on a
controlled network and restrict inbound UDP access with the host/network
firewall. Binding to port 53 may require elevated privileges.

Test a query with:

```sh
dig @127.0.0.1 -p 5300 example.com A
```

Run the protocol and cache tests with:

```sh
python3 -m unittest discover -s tests -v
```
