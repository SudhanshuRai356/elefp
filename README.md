# elefp - post quantum vpn that actually works

basically i got tired of vpns that will get broken by quantum computers in a few years so i made one that wont. uses kyber512 which is quantum resistant and all that good stuff.

## what this thing does

- **post quantum crypto** - kyber512 kem for key exchange, so quantum computers can cry about it
- **proper vpn functionality** - full tunneling, nat, routing, ip allocation, the works 
- **fast as hell** - multithreaded server, can handle 50+ clients easy
- **tun interfaces** - real network tunneling, not some toy implementation
- **dynamic ip allocation** - dhcp-like ip management for clients
- **internet access** - full nat support so you can actually browse the web
- **linux ready** - works on linux, might work on other stuff later

## the crypto stack (this is the important part)

```
kyber512 (post-quantum kem) -> hkdf-sha256 -> aes-256-gcm
```

- **kyber512**: post quantum key encapsulation mechanism, this is what makes it quantum resistant
- **hkdf**: key derivation function using sha256, stretches the kyber shared secret  
- **aes-256-gcm**: authenticated encryption, so packets cant be tampered with

basically when you connect:
1. client generates kyber keypair
2. server encapsulates and gets shared secret
3. both sides use hkdf to derive session keys  
4. all packets encrypted with aes-gcm using derived keys

## how to build this thing

you need some deps first:
```bash
# ubuntu/debian
sudo apt-get install build-essential cmake ninja-build pkg-config git libssl-dev libasio-dev
```

### 1) get liboqs source in external/liboqs

this repo tracks liboqs as a submodule, so from repo root run:

```bash
git submodule update --init --recursive external/liboqs
```

if you cloned without submodule metadata, clone directly:

```bash
git clone https://github.com/open-quantum-safe/liboqs external/liboqs
```

### 2) build static liboqs.a (required)

the project links directly to this path:

`external/liboqs/build/lib/liboqs.a`

build it like this:

```bash
cmake -S external/liboqs -B external/liboqs/build -G Ninja \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_ENABLE_KEM_KYBER=ON \
  -DOQS_ENABLE_KEM_KYBER_512=ON \
  -DOQS_DIST_BUILD=OFF

cmake --build external/liboqs/build -j"$(nproc)"
```

quick sanity check:

```bash
test -f external/liboqs/build/lib/liboqs.a && echo "liboqs.a found"
test -f external/liboqs/build/include/oqs/oqs.h && echo "liboqs headers found"
```

### 3) build elefp

```bash
cmake -S . -B build -G Ninja
cmake --build build -j"$(nproc)"
```

if cmake complains about missing oqs headers or library, it means the liboqs build step above did not complete in `external/liboqs/build`.

## actually using it

### server
```bash
# needs root for tun interface
sudo ./vpn_server --generate-config  # makes default config
sudo ./vpn_server --verbose          # start with debug output
```

server will:
- create tun0 interface with ip 10.8.0.1  
- listen on udp port 1194
- allocate ips 10.8.0.10-100 to clients
- route packets between clients and internet

### client  
```bash
sudo ./vpn_client --server 127.0.0.1 --verbose
```

client will:
- connect to server with post quantum handshake
- get assigned an ip in 10.8.0.x range
- create local tun interface  
- route all traffic through vpn tunnel

## the actual tech behind this (in depth)

### network architecture
```
[client app] -> [tun interface] -> [vpn client] -> [udp] -> [vpn server] -> [tun interface] -> [internet]
```

the tun interface captures all ip packets from applications, encrypts them, sends over udp to server. server decrypts and either routes to another client or sends to internet via nat.

### packet format on the wire  
```
[1 byte type][4 bytes length][12 bytes nonce][encrypted payload][16 bytes auth tag]
```

- type: packet type (data, handshake, keepalive etc)
- length: size of encrypted payload  
- nonce: random nonce for aes-gcm (never reused)
- payload: actual ip packet encrypted with aes-gcm
- auth tag: message authentication from gcm mode

### ip allocation system
- server manages pool of 10.8.0.10-100 (90 ips available)
- when client connects gets assigned next free ip
- mapping stored: client_id -> ip and reverse lookup ip -> client_id  
- released when client disconnects or session times out

### nat implementation
- server does network address translation for internet access  
- tracks connections: internal_ip:port -> external_port mapping
- rewrites packet headers for outbound (client -> internet)  
- rewrites packet headers for inbound (internet -> client)
- connection tracking with 5min timeout for unused connections

### routing engine
- packet comes in, parse ip header to get destination
- if dest ip is another vpn client: route directly client-to-client
- if dest ip is internet: apply nat and forward to real interface  
- maintains routing table and metrics for path selection

### session management  
- each client gets session with unique crypto keys
- session includes: client_id, assigned_ip, crypto_context, last_activity
- server can handle multiple sessions concurrently with thread pool
- sessions timeout after inactivity and get cleaned up

### threading model
- main thread: accepts new connections and handles handshakes
- worker threads: process encrypted packets and routing  
- packet router runs in multiple threads for performance
- all data structures are thread-safe with proper locking

### performance optimizations
- zero-copy packet handling where possible
- preallocated packet buffers to avoid malloc in hot path
- connection pooling and reuse for nat entries
- efficient hash maps for client and nat lookups
- batch processing of packets when under load

### security considerations  
- perfect forward secrecy: new session keys for each connection
- replay protection: sequence numbers in packet headers  
- timing attack prevention: constant time crypto operations
- memory safety: modern c++17 with smart pointers and containers
- privilege separation: different components run with minimal required privs

## testing  
```bash
make run-tests        # all tests
./crypto_test         # just crypto stuff
./vpn_component_test  # vpn components  
sudo ./vpn_integration_test  # full system test (needs root)
```

crypto tests verify kyber/hkdf/aes implementation.  
component tests verify ip pools, routing, config parsing.
integration tests verify full vpn functionality with tun interfaces.

## why this is better than other vpns

1. **quantum resistant crypto** - most vpns use ecdh which quantum computers will break
2. **proper security** - perfect forward secrecy, authenticated encryption, replay protection
3. **real performance** - multithreaded architecture, not single threaded like some others  
4. **actual vpn features** - full routing, nat, ip allocation, not just a tunnel
5. **open source** - you can audit the crypto and implementation
6. **linux native** - designed for linux performance, not cross platform compromise

## files you care about

- `src/crypto/` - the post quantum crypto implementation  
- `src/transport/` - packet handling and secure sessions
- `src/vpn/` - tun interfaces, routing, nat, ip management
- `test/` - comprehensive test suite
- `external/liboqs/` - post quantum crypto library

the crypto stuff in src/crypto/ is where the magic happens. keyexchange.cpp does the kyber operations, aesgcm.cpp handles packet encryption, hkdf.cpp derives the session keys.

## config

both server and client can use config files:

### server config (~/.config/elefp/server.conf)  
```ini
listen_address = 0.0.0.0
listen_port = 1194
server_ip = 10.8.0.1  
client_ip_range_start = 10.8.0.10
client_ip_range_end = 10.8.0.100
max_clients = 50
enable_internet_access = true
dns_servers = 8.8.8.8,8.8.4.4
```

### client config (~/.config/elefp/client.conf)
```ini  
server_address = 127.0.0.1
server_port = 1194
auto_reconnect = true
redirect_gateway = true  
dns_servers = 8.8.8.8,8.8.4.4
```

## troubleshooting  

**"permission denied creating tun"** - run with sudo, tun interfaces need root  
**"connection timeout"** - check firewalls, verify server is running  
**"handshake failed"** - crypto mismatch, check liboqs build  
**"no route to host"** - routing tables messed up, check ip forwarding enabled

run with `--verbose` flag to see detailed logging of whats happening.

## future plans

- windows/macos support (needs different tun interface code)
- web admin interface for server management  
- mobile clients for android/ios
- performance optimizations for 1000+ clients
- maybe switch to kyber1024 if needed for higher security
- wireguard-style config format for easier deployment  

the core crypto and vpn functionality is solid, just needs polish and platform support.

## license  

MIT License. See [LICENSE](LICENSE). 

---

tldr: quantum resistant vpn that actually works and is fast. uses kyber512 + aes, handles real network traffic, supports multiple clients. not a toy.

```bash
# Generate default configuration  
sudo ./vpn_client --generate-config

# Connect to server (requires root for TUN interface and routing)
sudo ./vpn_client --server 127.0.0.1 --verbose
```

## Usage

### Server Options

```bash
./vpn_server [OPTIONS]
  -c, --config FILE      Configuration file path
  -p, --port PORT        Listen port (default: 1194) 
  -a, --address ADDR     Listen address (default: 0.0.0.0)
  -i, --interface NAME   TUN interface name
  -m, --max-clients N    Maximum clients (default: 50)
  -t, --threads N        Worker threads (default: 4)
  -d, --daemon           Run as daemon
  -v, --verbose          Verbose output
  --generate-config      Generate default config
```

### Client Options

```bash
./vpn_client [OPTIONS]
  -c, --config FILE      Configuration file path
  -s, --server ADDRESS   Server address (default: 127.0.0.1)
  -p, --port PORT        Server port (default: 1194)
  -i, --interface NAME   TUN interface name
  -r, --no-redirect      Don't redirect default gateway
  -a, --auto-reconnect   Enable auto-reconnection
  -t, --timeout SECONDS  Connection timeout (default: 30)
  -v, --verbose          Verbose output
  --status               Show connection status
  --test-connectivity    Test connectivity
```

## Configuration

### Server Configuration (`~/.config/elefp/server.conf`)

```ini
# Network Settings
listen_address = 0.0.0.0
listen_port = 1194  
server_ip = 10.8.0.1
server_netmask = 255.255.255.0
client_ip_range_start = 10.8.0.10
client_ip_range_end = 10.8.0.100

# Performance
max_clients = 50
worker_threads = 4
session_timeout_seconds = 300

# Features
enable_internet_access = true
dns_servers = 8.8.8.8,8.8.4.4
```

### Client Configuration (`~/.config/elefp/client.conf`)

```ini
# Connection
server_address = 127.0.0.1
server_port = 1194

# Routing
redirect_gateway = true
dns_servers = 8.8.8.8,8.8.4.4

# Reconnection
auto_reconnect = true
max_reconnect_attempts = 10
reconnect_delay_seconds = 5
```

## Testing

```bash
# Run all tests
make run-tests

# Run specific tests
./crypto_test           # Crypto functionality
./vpn_component_test   # VPN components  
./vpn_integration_test # Integration tests
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   VPN Client    │────▶│   VPN Server    │
│                 │     │                 │
│ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │ TUN Interface│ │     │ │ TUN Interface│ │
│ └─────────────┘ │     │ └─────────────┘ │
│ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │SecureSession│ │◄───▶│ │SessionManager│ │
│ └─────────────┘ │     │ └─────────────┘ │
│ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │ KeyExchange │ │     │ │ PacketRouter│ │
│ └─────────────┘ │     │ └─────────────┘ │
└─────────────────┘     │ ┌─────────────┐ │
                        │ │   IpPool    │ │
                        │ └─────────────┘ │
                        └─────────────────┘
```

## Security

- **Post-quantum security**: Uses Kyber512 for quantum-resistant key exchange
- **Perfect forward secrecy**: New session keys for each connection
- **Authenticated encryption**: AES-256-GCM prevents tampering
- **Replay protection**: Sequence numbers prevent replay attacks

## Requirements

- **Linux**: Primary target platform
- **Root privileges**: Required for TUN interface creation and routing
- **CMake 3.16+**: Build system
- **C++17**: Compiler support  
- **OpenSSL**: Cryptographic functions
- **ASIO**: Asynchronous networking (header-only)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

## Troubleshooting

### Common Issues

**Permission denied creating TUN interface**
- Run with `sudo` or configure appropriate permissions

**Connection timeout**
- Check firewall settings
- Verify server is listening on correct port
- Check network connectivity

**Cannot resolve server address**
- Verify DNS resolution or use IP address
- Check `/etc/hosts` for local testing

For more help, run with `--verbose` flag for detailed logging.
