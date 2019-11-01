# Coroxy
A simple HTTP proxy server to prevent attacks to your private network.

## Configuration Example
```yaml
# Blocks loopback and multicast
allowGlobalUnicastOnly: true

# Blocks private addresses
blockPrivateAddressV4: true

blacklist:
  # IP address
  - "192.168.1.1"
  # CIDR
  - "192.168.1.0/24"
  # Blocks connections to the ports not specified in `portWhitelist`
  - addr: "192.168.1.2"
    portWhitelist:
      - 80
      - 8000-8080
  # Blocks connections to the ports
  - addr: "192.168.2.0/24"
    portBlacklist: 443
```
