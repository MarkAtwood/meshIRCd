# MeshIRCd

A federated IRC server for hobbyist networks. Modern protocol internals, classic IRC interface.

## What It Is

MeshIRCd is a from-scratch IRC server in Go that federates with other MeshIRCd servers over a custom S2S protocol. Clients connect with any standard IRC client. Servers find each other via a shared GitHub repository.

## What Makes It Different

**JSON-LD S2S Protocol**  
Server-to-server communication uses JSON-LD over TLS. Events are signed with Ed25519, ordered with Lamport clocks, and deduplicated across the mesh. No TS6, no services, no legacy baggage.

**GitHub-Based Discovery**  
Servers find peers by polling a `servers.json` file in a GitHub repo. Join the network with a PR. Leave by deleting your entry. Git history is your audit log.

**DID Identity**  
Users can attach Decentralized Identifiers to their presence. Prove you control `did:key:...` or `did:web:example.com`. Identity propagates across the federation and shows in WHOIS.

**IRCv3 Features**  
SASL EXTERNAL (TLS client certs mapped to DIDs), message IDs, echo-message, chathistory, labeled-response. Modern client UX on a modern server.

**Soft Mesh Topology**  
Servers connect to all peers they can reach. Messages flood with deduplication. No spanning tree, no single point of failure. Partitions heal automatically.

## Architecture

```
┌──────────────┐    JSON-LD/TLS     ┌──────────────┐
│  MeshIRCd A  │◄──────────────────►│  MeshIRCd B  │
└──────┬───────┘                    └───────┬──────┘
       │ IRC                                │ IRC
       ▼                                    ▼
   ┌───────┐                            ┌───────┐
   │ irssi │                            │ weechat│
   └───────┘                            └───────┘
```

- **C2S**: Standard IRC protocol + IRCv3 extensions
- **S2S**: JSON-LD messages, Ed25519 signatures, Lamport ordering
- **Discovery**: GitHub repo with `servers.json`

## Quick Start

```bash
# Generate keypair and server config
meshircd --init --hostname irc.example.com --port 6697 --admin you@example.com

# Start the server
meshircd \
  --hostname irc.example.com \
  --port 6697 \
  --cert server.crt \
  --key server.key \
  --discovery-url https://raw.githubusercontent.com/MarkAtwood/meshircd-network/main/servers.json
```

## Joining a Network

1. Run `meshircd --init` to generate your server block
2. Fork the network's config repo
3. Add your block to `servers.json`
4. Open a PR
5. Wait for merge
6. Start your server — peers connect within 5 minutes

## Configuration

**servers.json** (in your network's GitHub repo):

```json
{
  "network": "MyNetwork",
  "servers": {
    "irc.example.com": {
      "port": 6697,
      "pubkey": "ed25519:MCowBQYDK2VwAyEA...",
      "admin": "admin@example.com"
    }
  }
}
```

## Identity

Users can attach DIDs to their IRC presence:

```
/quote IDENTITY CHALLENGE
/quote METADATA * SET identity :{"@context":[...],"id":"did:key:z6Mk...","proof":{...}}
```

Identity shows in WHOIS and propagates across the federation.

## Specs

| Document | Description |
|----------|-------------|
| [S2S.md](S2S.md) | Server-to-server federation protocol |
| [IDENTITY.md](IDENTITY.md) | DID-based identity extension |
| [IRCV3.md](IRCV3.md) | IRCv3 client protocol extensions |
| [DISCOVERY.md](DISCOVERY.md) | GitHub-based peer discovery |

## Building

```bash
go build -o meshircd .
```

Requires Go 1.21+.

## Docker

```bash
# Build
docker build -t meshircd .

# Initialize (generates keys, outputs servers.json block)
docker run --rm -v meshircd-data:/data \
  -e MESHIRCD_HOSTNAME=irc.example.com \
  -e MESHIRCD_ADMIN=you@example.com \
  meshircd --init

# Run
docker run -d --name meshircd \
  -v meshircd-data:/data \
  -p 6697:6697 \
  -e MESHIRCD_HOSTNAME=irc.example.com \
  -e MESHIRCD_DISCOVERY_URL=https://raw.githubusercontent.com/MarkAtwood/meshircd-network/main/servers.json \
  meshircd
```

Environment variables:
- `MESHIRCD_HOSTNAME` — server hostname (required)
- `MESHIRCD_DISCOVERY_URL` — servers.json URL for federation
- `MESHIRCD_NETWORK` — network name (default: MeshIRCd)
- `MESHIRCD_ADMIN` — admin email (for init)
- `MESHIRCD_DATA` — data directory (default: /data)

Keys persist in the `/data` volume. First run with `--init`, PR the output block to the network repo, then run normally.

## Running Behind a Reverse Proxy

MeshIRCd can run behind Caddy or another proxy using TCP passthrough. TLS must terminate at MeshIRCd (not the proxy) so federation peers see the correct certificate.

**Caddy with layer4 plugin:**

```
# Caddyfile
{
  layer4 {
    :6697 {
      route {
        proxy meshircd-backend:6697
      }
    }
  }
}
```

Build Caddy with the layer4 plugin:
```bash
xcaddy build --with github.com/mholt/caddy-l4
```

This works well for homelab setups where MeshIRCd runs on an internal server (e.g., via Tailscale) and Caddy runs on a public VPC.

## Design Principles

- **TLS only** — no plaintext, no STARTTLS upgrade dance
- **No services** — identity is DIDs, not NickServ
- **No linking complexity** — soft mesh, not spanning tree
- **Git as coordination** — PRs for trust decisions, history for audit
- **JSON-LD for extensibility** — add contexts, not protocol versions
- **Existing clients work** — IRCv3 where it helps, standard IRC everywhere

## License

AGPL-3.0
