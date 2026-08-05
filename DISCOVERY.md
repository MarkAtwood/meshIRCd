# Server Discovery

GitHub-based peer discovery for federated IRC. Servers find each other via a shared repository. Join the network with a PR.

## Overview

- **Config source**: GitHub repository with `servers.json`
- **Trust model**: PR approval = network membership
- **Key distribution**: Ed25519 public keys in config
- **Updates**: Poll every 5 minutes, cache locally
- **No central coordination**: Git is the only shared state

## Repository Structure

```
network-name/
├── servers.json        # Server list with keys
├── network.json        # Network metadata (optional)
├── contexts/           # JSON-LD contexts (optional)
│   ├── s2s-v1.jsonld
│   ├── identity-v1.jsonld
│   └── ...
└── README.md
```

## servers.json

### Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["network", "servers"],
  "properties": {
    "network": {
      "type": "string",
      "description": "Network name displayed to users"
    },
    "version": {
      "type": "integer",
      "description": "Config version, increment on changes"
    },
    "servers": {
      "type": "object",
      "additionalProperties": {
        "$ref": "#/$defs/server"
      }
    }
  },
  "$defs": {
    "server": {
      "type": "object",
      "required": ["port", "pubkey"],
      "properties": {
        "port": {
          "type": "integer",
          "minimum": 1,
          "maximum": 65535
        },
        "pubkey": {
          "type": "string",
          "pattern": "^ed25519:[A-Za-z0-9+/=]+$"
        },
        "admin": {
          "type": "string",
          "format": "email"
        },
        "location": {
          "type": "string",
          "description": "Geographic hint (e.g., 'US-West', 'EU-Central')"
        },
        "description": {
          "type": "string"
        }
      }
    }
  }
}
```

### Example

```json
{
  "network": "CoolIRC",
  "version": 42,
  "servers": {
    "irc.example.com": {
      "port": 6697,
      "pubkey": "ed25519:MCowBQYDK2VwAyEA1J9dS7eLBKJwPxjE4jX5dlHjK...",
      "admin": "alice@example.com",
      "location": "US-West",
      "description": "Primary server"
    },
    "irc.friend.net": {
      "port": 6697,
      "pubkey": "ed25519:MCowBQYDK2VwAyEA7kD3HqT9LmN2pQrS5vW8xYz...",
      "admin": "bob@friend.net",
      "location": "EU-Central"
    },
    "irc.third.org": {
      "port": 6697,
      "pubkey": "ed25519:MCowBQYDK2VwAyEAqR4sT6uV2wX8yZ0aBcDeFgH...",
      "admin": "carol@third.org",
      "location": "Asia-East"
    }
  }
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `network` | yes | Network name for ISUPPORT, WHOIS, welcome |
| `version` | no | Integer version, helps detect changes |
| `servers` | yes | Map of hostname → server config |
| `servers.*.port` | yes | TLS port (typically 6697) |
| `servers.*.pubkey` | yes | Ed25519 public key, `ed25519:` prefix + base64 |
| `servers.*.admin` | no | Contact email |
| `servers.*.location` | no | Geographic hint for users |
| `servers.*.description` | no | Human-readable description |

## network.json (Optional)

Network-wide settings:

```json
{
  "name": "CoolIRC",
  "description": "A modern federated IRC network",
  "website": "https://coolirc.example",
  "policies": {
    "minTLSVersion": "1.3",
    "requiredCaps": ["sasl", "message-ids"],
    "maxNickLength": 30,
    "maxChannelLength": 50
  },
  "contexts": {
    "s2s": "https://raw.githubusercontent.com/network-name/config/main/contexts/s2s-v1.jsonld",
    "identity": "https://raw.githubusercontent.com/network-name/config/main/contexts/identity-v1.jsonld"
  }
}
```

Servers SHOULD fetch this and apply policies. Non-compliant servers may be rejected by peers.

## Key Format

### Generation

```bash
# Generate Ed25519 keypair
openssl genpkey -algorithm ED25519 -out server.key

# Extract public key
openssl pkey -in server.key -pubout -out server.pub

# Base64 encode for servers.json
echo "ed25519:$(openssl pkey -in server.key -pubout -outform DER | base64)"
```

Or using Go:
```go
pub, priv, _ := ed25519.GenerateKey(rand.Reader)
fmt.Printf("ed25519:%s\n", base64.StdEncoding.EncodeToString(pub))
```

### Storage

- **Private key**: `server.key` — kept secret, used for TLS and S2S signing
- **Public key**: In `servers.json` — distributed to all peers

### TLS Certificate

Generate self-signed cert from the Ed25519 key:

```bash
openssl req -new -x509 -key server.key -out server.crt -days 3650 \
  -subj "/CN=irc.example.com"
```

Peers verify against pubkey in `servers.json`, not CA chain.

## Discovery Flow

### Startup

```
1. Load cached servers.json (if exists)
2. Fetch fresh servers.json from GitHub
   - URL: https://raw.githubusercontent.com/{org}/{repo}/main/servers.json
   - Or via GitHub API for private repos
3. If fetch succeeds:
   - Validate JSON schema
   - Compare version to cached
   - Update cache
4. If fetch fails:
   - Log warning
   - Use cached version
   - If no cache, abort startup
5. For each server in list (except self):
   - Initiate TLS connection
   - Verify peer cert against pubkey
   - Exchange Hello, sync state
```

### Periodic Refresh

```
Every 5 minutes:
1. Fetch servers.json
2. If changed:
   - Diff against current
   - Connect to new servers
   - Disconnect from removed servers
   - Log key changes (security event)
3. If fetch fails:
   - Keep using current config
   - Retry next interval
```

### Configuration

Command-line flags:

```
--discovery-url    GitHub raw URL for servers.json
--discovery-poll   Poll interval (default: 5m)
--discovery-cache  Local cache path (default: ~/.ircd/servers.json)
```

Or via config file:

```yaml
discovery:
  url: https://raw.githubusercontent.com/coolnetwork/config/main/servers.json
  poll: 5m
  cache: /var/lib/ircd/servers.json
```

## Joining the Network

### Prerequisites

1. Running IRC server with TLS
2. Ed25519 keypair generated
3. GitHub account

### Steps

1. **Fork the config repository**

2. **Generate your server block**:
   ```bash
   meshircd --init --hostname irc.yourserver.com --port 6697
   ```
   
   Outputs:
   ```json
   {
     "irc.yourserver.com": {
       "port": 6697,
       "pubkey": "ed25519:MCowBQYDK2VwAyEA...",
       "admin": "you@yourserver.com"
     }
   }
   ```

3. **Add to servers.json** in your fork

4. **Open PR** with:
   - Your server block added
   - Brief description (who you are, why joining)

5. **Wait for review**
   - Existing operators review
   - May ask for verification (prove you control the domain)
   - Merge = you're in

6. **Start your server**
   - Point `--discovery-url` at the repo
   - Within 5 minutes, all peers connect to you

### PR Template

```markdown
## New Server: irc.yourserver.com

**Admin**: your@email.com
**Location**: US-West
**Description**: Personal server for friends

### Verification
- [ ] Domain ownership: [link to DNS TXT record or webpage]
- [ ] Server is running and reachable
- [ ] TLS certificate valid

### Server Block
```json
{
  "irc.yourserver.com": {
    "port": 6697,
    "pubkey": "ed25519:...",
    "admin": "your@email.com",
    "location": "US-West"
  }
}
```
```

## Leaving the Network

### Graceful Exit

1. Open PR removing your server block
2. Wait for merge
3. Peers disconnect within 5 minutes
4. Shut down server

### Emergency Removal

If a server is compromised or abusive:

1. Any operator opens PR removing it
2. Fast-track review (security issue)
3. Merge ASAP
4. All peers disconnect on next poll

Consider: GitHub Actions to notify operators of removal PRs.

## Key Rotation

### Process

1. Generate new keypair
2. Open PR updating your pubkey
3. Coordinate in PR comments: "Rotating at 3pm UTC"
4. Merge PR
5. Restart server with new key
6. Peers reconnect within 5 minutes

### No Grace Period

Hard cutover. Brief disconnection is acceptable for hobbyist network. If you need zero-downtime rotation, coordinate manually:

1. Announce in network channel
2. Merge PR
3. Restart immediately
4. Peers retry connection, succeed with new key

## Peer Verification

### TLS Handshake

1. Server presents TLS certificate
2. Client extracts public key from cert
3. Client compares to `pubkey` in servers.json
4. Mismatch = reject connection, log security event

### Implementation

```go
func verifyPeer(conn *tls.Conn, expectedPubkey ed25519.PublicKey) error {
    certs := conn.ConnectionState().PeerCertificates
    if len(certs) == 0 {
        return errors.New("no peer certificate")
    }
    
    peerPubkey, ok := certs[0].PublicKey.(ed25519.PublicKey)
    if !ok {
        return errors.New("not an Ed25519 key")
    }
    
    if !bytes.Equal(peerPubkey, expectedPubkey) {
        return errors.New("pubkey mismatch")
    }
    
    return nil
}
```

### Certificate Requirements

- MUST use Ed25519 key (matches pubkey in config)
- SHOULD set CN to hostname
- MAY be self-signed (CA not required)
- SHOULD have reasonable expiry (1-10 years)

## Caching

### Local Cache

Servers MUST cache `servers.json` locally:

```
~/.ircd/servers.json         # or configured path
~/.ircd/servers.json.etag    # HTTP ETag for conditional fetch
~/.ircd/servers.json.fetched # Last successful fetch timestamp
```

### Cache Behavior

| Scenario | Behavior |
|----------|----------|
| Fresh start, no cache | Fetch required, fail = abort |
| Fresh start, have cache | Fetch, fallback to cache on failure |
| Running, fetch succeeds | Update cache |
| Running, fetch fails | Keep using current, log warning |
| Cache older than 24h | Log warning, consider degraded |

### Conditional Fetch

Use `If-None-Match` with ETag to reduce bandwidth:

```http
GET /org/repo/main/servers.json HTTP/1.1
Host: raw.githubusercontent.com
If-None-Match: "abc123"
```

304 Not Modified = no change, skip processing.

## Private Networks

For non-public networks, use a private GitHub repository:

### GitHub Token

```bash
meshircd --discovery-url https://api.github.com/repos/org/private-config/contents/servers.json \
     --discovery-token ghp_xxxx
```

### Token Permissions

Minimum required: `repo` read access to the config repository.

Store token securely:
- Environment variable: `IRCD_GITHUB_TOKEN`
- Secrets manager
- NOT in command line (visible in ps)

## Failure Modes

### GitHub Unreachable

- Use cached config
- Retry every poll interval
- Log warnings
- After 24h, consider manual intervention

### Invalid JSON

- Reject update
- Keep previous valid config
- Log error with details
- Alert operators (if alerting configured)

### Unknown Server Connecting

If a server connects but isn't in servers.json:

- Reject connection
- Log security event: hostname, IP, presented pubkey
- Do NOT add dynamically (trust is via Git)

### Key Mismatch

If known server connects with different key:

- Reject connection
- Log security event
- Possible causes:
  - Key rotation in progress (wait for poll)
  - Compromise (alert operators)
  - Misconfiguration

## GitHub Actions (Optional)

Automate validation and notification:

### PR Validation

`.github/workflows/validate.yml`:

```yaml
name: Validate Config

on:
  pull_request:
    paths:
      - 'servers.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Validate JSON Schema
        run: |
          npm install -g ajv-cli
          ajv validate -s schema.json -d servers.json
      
      - name: Check for duplicate hostnames
        run: |
          jq -e '.servers | keys | unique | length == (.servers | keys | length)' servers.json
      
      - name: Verify pubkey format
        run: |
          jq -r '.servers[].pubkey' servers.json | while read key; do
            [[ $key =~ ^ed25519:[A-Za-z0-9+/=]+$ ]] || exit 1
          done
```

### Change Notification

`.github/workflows/notify.yml`:

```yaml
name: Notify on Merge

on:
  push:
    branches: [main]
    paths:
      - 'servers.json'

jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - name: Send webhook
        run: |
          curl -X POST ${{ secrets.WEBHOOK_URL }} \
            -H "Content-Type: application/json" \
            -d '{"event": "config_updated", "repo": "${{ github.repository }}"}'
```

Servers can expose a `/reload` webhook to trigger immediate fetch.

## Security Considerations

1. **GitHub as trust root** — whoever can merge controls the network
2. **Branch protection** — require PR reviews, no direct pushes to main
3. **Key custody** — private keys never in repo, only pubkeys
4. **Audit log** — Git history shows all changes, who made them, when
5. **Revocation speed** — 5 minute poll = 5 minute max exposure after merge
6. **Token security** — for private repos, protect GitHub tokens
7. **DNS** — hostname in config should match DNS; consider DNSSEC

## CLI Reference

### meshircd --init

Generate server config block for joining:

```bash
meshircd --init --hostname irc.example.com --port 6697 --admin alice@example.com
```

Output:
```json
{
  "irc.example.com": {
    "port": 6697,
    "pubkey": "ed25519:...",
    "admin": "alice@example.com"
  }
}
```

Also generates `server.key` and `server.crt` if they don't exist.

### meshircd --check-config

Validate a servers.json:

```bash
meshircd --check-config servers.json
```

Checks:
- Valid JSON
- Schema compliance
- Pubkey format
- No duplicate hostnames

### meshircd --test-peer

Test connectivity to a peer:

```bash
meshircd --test-peer irc.friend.net --config servers.json
```

Attempts TLS connection, verifies pubkey, sends Hello, reports result.

## Example: Full Bootstrap

```bash
# 1. Generate keypair and config
meshircd --init --hostname irc.myserver.com --port 6697 --admin me@myserver.com > my-server.json

# 2. Fork config repo, add your block, open PR, wait for merge

# 3. Start server
meshircd \
  --hostname irc.myserver.com \
  --port 6697 \
  --cert server.crt \
  --key server.key \
  --discovery-url https://raw.githubusercontent.com/coolnetwork/config/main/servers.json

# 4. Verify peers connected
meshircdctl status
# Output:
# Peers: 3 connected
#   irc.example.com: connected, synced, 1234 events
#   irc.friend.net: connected, synced, 567 events
#   irc.third.org: connected, syncing...
```
