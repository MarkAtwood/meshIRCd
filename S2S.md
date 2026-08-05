# IRC S2S Federation Protocol

Server-to-server protocol for hobbyist IRC federation. JSON-LD over TLS with Lamport clocks and Ed25519 signatures.

## Overview

- **Transport**: TLS 1.3, mutual authentication via Ed25519 keys
- **Framing**: Newline-delimited JSON-LD
- **Ordering**: Lamport clocks, deterministic conflict resolution
- **Discovery**: GitHub repo with `servers.json`
- **Topology**: Soft mesh, flood-with-dedupe routing

## Identifiers

URN schemes for all entities:

| Entity | Format | Example |
|--------|--------|---------|
| Server | `urn:irc:server:<hostname>` | `urn:irc:server:irc.example.com` |
| User | `urn:irc:user:<server>:<nick>` | `urn:irc:user:irc.example.com:alice` |
| Channel | `urn:irc:channel:<name>` | `urn:irc:channel:foo` |
| Event | `urn:irc:event:<server>:<seq>` | `urn:irc:event:irc.example.com:12345` |

Channel names omit the `#` prefix in URNs (it's implied).

## Context Document

Hosted at `https://ns.ircd.example/s2s/v1` (or embedded inline):

```json
{
  "@context": {
    "@version": 1.1,
    "@vocab": "https://ns.ircd.example/s2s#",
    
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "sec": "https://w3id.org/security#",
    
    "id": "@id",
    "type": "@type",
    
    "seq":       {"@id": "s2s:sequence", "@type": "xsd:integer"},
    "origin":    {"@id": "s2s:origin", "@type": "@id"},
    "ts":        {"@id": "s2s:timestamp", "@type": "xsd:dateTime"},
    "sig":       {"@id": "sec:signature"},
    "sigAlg":    {"@id": "sec:signatureAlgorithm"},
    
    "nick":      "s2s:nickname",
    "ident":     "s2s:ident",
    "host":      "s2s:hostname",
    "realname":  "s2s:realname",
    "channel":   {"@id": "s2s:channel", "@type": "@id"},
    "user":      {"@id": "s2s:user", "@type": "@id"},
    "from":      {"@id": "s2s:from", "@type": "@id"},
    "to":        {"@id": "s2s:to", "@type": "@id"},
    "text":      "s2s:messageText",
    "reason":    "s2s:reason",
    "modes":     "s2s:modes",
    "topic":     "s2s:topic",
    "caps":      {"@id": "s2s:capabilities", "@container": "@set"},
    "vector":    {"@id": "s2s:syncVector", "@container": "@index"},
    "events":    {"@id": "s2s:events", "@container": "@list"},
    "members":   {"@id": "s2s:members", "@container": "@set"},
    "bans":      {"@id": "s2s:bans", "@container": "@set"},
    
    "Server":         "s2s:Server",
    "User":           "s2s:User",
    "Channel":        "s2s:Channel",
    "ChannelMember":  "s2s:ChannelMember",
    "Ban":            "s2s:Ban",
    
    "Hello":          "s2s:Hello",
    "Ping":           "s2s:Ping",
    "Pong":           "s2s:Pong",
    "UserOnline":     "s2s:UserOnline",
    "UserOffline":    "s2s:UserOffline",
    "NickChange":     "s2s:NickChange",
    "Join":           "s2s:Join",
    "Part":           "s2s:Part",
    "Kick":           "s2s:Kick",
    "ChannelMessage": "s2s:ChannelMessage",
    "PrivateMessage": "s2s:PrivateMessage",
    "Notice":         "s2s:Notice",
    "Mode":           "s2s:Mode",
    "Topic":          "s2s:Topic",
    "SyncRequest":    "s2s:SyncRequest",
    "SyncResponse":   "s2s:SyncResponse",
    "Error":          "s2s:Error",
    "IdentityUpdate": "s2s:IdentityUpdate"
  }
}
```

## Message Envelope

All messages share this structure:

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "MessageType",
  "@id": "urn:irc:event:<origin>:<seq>",
  "seq": 12345,
  "origin": "urn:irc:server:<hostname>",
  "ts": "2026-08-05T14:23:00Z",
  "sig": "<base64-encoded-ed25519-signature>",
  "sigAlg": "ed25519",
  ...
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `@context` | string/array | yes | Context URL(s) |
| `@type` | string | yes | Message type |
| `@id` | URN | yes | Unique event identifier |
| `seq` | integer | yes | Lamport sequence number |
| `origin` | URN | yes | Server that created this event |
| `ts` | ISO 8601 | yes | Wall clock time (informational) |
| `sig` | string | yes | Ed25519 signature (base64) |
| `sigAlg` | string | yes | Always `"ed25519"` for now |

## Signatures

Sign the **compacted canonical form**:
1. Remove `sig` and `sigAlg` fields
2. Compact against the context
3. Serialize with sorted keys, no whitespace
4. Sign with Ed25519 private key
5. Encode signature as base64

Verification:
1. Extract and remove `sig` and `sigAlg`
2. Compact and canonicalize
3. Verify against origin server's public key from `servers.json`

## Lamport Clocks

Each server maintains:
- Local sequence counter (increments on every outgoing event)
- Vector clock: `{server_urn: last_seen_seq}` for all known servers

On receiving an event:
```
local_seq = max(local_seq, event.seq) + 1
vector[event.origin] = max(vector[event.origin], event.seq)
```

Conflict resolution (e.g., nick collision):
- Lower `(seq, origin)` tuple wins
- Lexicographic comparison on origin URN as tiebreaker

## Message Types

### Connection Lifecycle

#### Hello

Sent immediately after TLS handshake. Initiates sync.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "Hello",
  "@id": "urn:irc:event:irc.example.com:1",
  "seq": 1,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:00:00Z",
  "caps": ["delta-sync", "reactions", "threading"],
  "vector": {
    "urn:irc:server:irc.example.com": 12345,
    "urn:irc:server:irc.friend.net": 8800
  },
  "sig": "...",
  "sigAlg": "ed25519"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `caps` | set of strings | Supported extensions |
| `vector` | map | Current sync vector |

#### Ping / Pong

Keepalive. Send `Ping` every 30 seconds, expect `Pong` within 10 seconds.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "Ping",
  "@id": "urn:irc:event:irc.example.com:12346",
  "seq": 12346,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:00:30Z",
  "nonce": "random-string",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "Pong",
  "@id": "urn:irc:event:irc.friend.net:8801",
  "seq": 8801,
  "origin": "urn:irc:server:irc.friend.net",
  "ts": "2026-08-05T14:00:30Z",
  "nonce": "random-string",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

### User Events

#### UserOnline

User connected to a server.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "UserOnline",
  "@id": "urn:irc:event:irc.example.com:12347",
  "seq": 12347,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:01:00Z",
  "user": {
    "@type": "User",
    "@id": "urn:irc:user:irc.example.com:alice",
    "nick": "alice",
    "ident": "alice",
    "host": "user.example.com",
    "realname": "Alice Smith"
  },
  "sig": "...",
  "sigAlg": "ed25519"
}
```

#### UserOffline

User disconnected.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "UserOffline",
  "@id": "urn:irc:event:irc.example.com:12400",
  "seq": 12400,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T15:00:00Z",
  "user": "urn:irc:user:irc.example.com:alice",
  "reason": "Quit: goodbye",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

#### NickChange

User changed nickname.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "NickChange",
  "@id": "urn:irc:event:irc.example.com:12350",
  "seq": 12350,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:05:00Z",
  "user": "urn:irc:user:irc.example.com:alice",
  "oldNick": "alice",
  "newNick": "alice_away",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

After processing, the user URN becomes `urn:irc:user:irc.example.com:alice_away`.

#### IdentityUpdate

User identity changed (set or cleared). See [IDENTITY.md](IDENTITY.md) for full identity verification protocol.

```json
{
  "@context": [
    "https://ns.ircd.example/s2s/v1",
    "https://ns.ircd.example/identity/v1"
  ],
  "@type": "IdentityUpdate",
  "@id": "urn:irc:event:irc.example.com:12352",
  "seq": 12352,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:05:30Z",
  "user": "urn:irc:user:irc.example.com:alice",
  "identity": {
    "id": "did:key:z6Mk...",
    "proof": {...}
  },
  "sig": "...",
  "sigAlg": "ed25519"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `user` | URN | User whose identity changed |
| `identity` | object/null | Identity document with proof, or `null` to clear |

### Channel Events

#### Join

User joined a channel.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "Join",
  "@id": "urn:irc:event:irc.example.com:12351",
  "seq": 12351,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:06:00Z",
  "user": "urn:irc:user:irc.example.com:alice",
  "channel": "urn:irc:channel:foo",
  "modes": "o",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `modes` | string | Initial modes (e.g., `"o"` for op, `"v"` for voice, `""` for none) |

#### Part

User left a channel.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "Part",
  "@id": "urn:irc:event:irc.example.com:12360",
  "seq": 12360,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:30:00Z",
  "user": "urn:irc:user:irc.example.com:alice",
  "channel": "urn:irc:channel:foo",
  "reason": "Later!",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

#### Kick

User was kicked from a channel.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "Kick",
  "@id": "urn:irc:event:irc.example.com:12361",
  "seq": 12361,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:31:00Z",
  "channel": "urn:irc:channel:foo",
  "user": "urn:irc:user:irc.example.com:bob",
  "by": "urn:irc:user:irc.example.com:alice",
  "reason": "Spamming",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

#### Mode

Channel or user mode change.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "Mode",
  "@id": "urn:irc:event:irc.example.com:12362",
  "seq": 12362,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:32:00Z",
  "channel": "urn:irc:channel:foo",
  "by": "urn:irc:user:irc.example.com:alice",
  "changes": "+o bob",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

For user modes, omit `channel` and set `user` instead of `by`.

#### Topic

Channel topic change.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "Topic",
  "@id": "urn:irc:event:irc.example.com:12363",
  "seq": 12363,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:33:00Z",
  "channel": "urn:irc:channel:foo",
  "by": "urn:irc:user:irc.example.com:alice",
  "topic": "Welcome to #foo!",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

### Messages

#### ChannelMessage

Message to a channel (PRIVMSG).

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "ChannelMessage",
  "@id": "urn:irc:event:irc.example.com:12370",
  "seq": 12370,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:40:00Z",
  "channel": "urn:irc:channel:foo",
  "from": "urn:irc:user:irc.example.com:alice",
  "text": "Hello everyone!",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

#### PrivateMessage

Direct message between users.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "PrivateMessage",
  "@id": "urn:irc:event:irc.example.com:12371",
  "seq": 12371,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:41:00Z",
  "from": "urn:irc:user:irc.example.com:alice",
  "to": "urn:irc:user:irc.friend.net:bob",
  "text": "Hey Bob!",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

#### Notice

Same as ChannelMessage/PrivateMessage but `@type": "Notice"`. Should not trigger auto-replies.

### State Synchronization

#### SyncRequest

Request missing events based on vector clock.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "SyncRequest",
  "@id": "urn:irc:event:irc.friend.net:8850",
  "seq": 8850,
  "origin": "urn:irc:server:irc.friend.net",
  "ts": "2026-08-05T14:00:05Z",
  "vector": {
    "urn:irc:server:irc.example.com": 12340,
    "urn:irc:server:irc.friend.net": 8849,
    "urn:irc:server:irc.other.net": 5500
  },
  "sig": "...",
  "sigAlg": "ed25519"
}
```

#### SyncResponse

Events the peer is missing, plus optional full state snapshot.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "SyncResponse",
  "@id": "urn:irc:event:irc.example.com:12380",
  "seq": 12380,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:00:06Z",
  "events": [
    {"@type": "UserOnline", "@id": "urn:irc:event:irc.example.com:12341", ...},
    {"@type": "Join", "@id": "urn:irc:event:irc.example.com:12342", ...}
  ],
  "sig": "...",
  "sigAlg": "ed25519"
}
```

If the requestor is too far behind (events have been pruned), include a full state snapshot:

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "SyncResponse",
  "@id": "urn:irc:event:irc.example.com:12381",
  "seq": 12381,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:00:06Z",
  "fullSync": true,
  "users": [
    {
      "@type": "User",
      "@id": "urn:irc:user:irc.example.com:alice",
      "nick": "alice",
      "ident": "alice",
      "host": "user.example.com",
      "realname": "Alice Smith"
    }
  ],
  "channels": [
    {
      "@type": "Channel",
      "@id": "urn:irc:channel:foo",
      "topic": "Welcome!",
      "topicBy": "urn:irc:user:irc.example.com:alice",
      "topicTs": "2026-08-05T12:00:00Z",
      "modes": "nt",
      "members": [
        {"user": "urn:irc:user:irc.example.com:alice", "modes": "o"},
        {"user": "urn:irc:user:irc.friend.net:bob", "modes": ""}
      ],
      "bans": [
        {"mask": "*!*@spammer.net", "by": "urn:irc:user:irc.example.com:alice", "ts": "2026-08-01T00:00:00Z"}
      ]
    }
  ],
  "sig": "...",
  "sigAlg": "ed25519"
}
```

### Errors

#### Error

Protocol or processing error.

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "Error",
  "@id": "urn:irc:event:irc.example.com:12382",
  "seq": 12382,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:00:07Z",
  "code": "INVALID_SIGNATURE",
  "message": "Signature verification failed for event urn:irc:event:irc.friend.net:8851",
  "ref": "urn:irc:event:irc.friend.net:8851",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

Error codes:
- `INVALID_SIGNATURE` — signature verification failed
- `UNKNOWN_ORIGIN` — origin server not in servers.json
- `SEQ_REGRESSION` — seq number went backwards
- `UNKNOWN_TYPE` — unrecognized message type (forward compat: log and ignore)
- `MALFORMED` — JSON-LD parsing failed
- `SYNC_TOO_OLD` — requested events have been pruned, full sync required

## Conflict Resolution

### Nick Collision

When two users on different servers have the same nick after a netsplit heals:

1. Compare `(seq, origin)` of the `UserOnline` events
2. Lower tuple wins (keeps the nick)
3. Loser's server sends `UserOffline` with reason `"Nick collision"`
4. Loser's server notifies local client with `KILL` message

### Channel State Merge

When partitions rejoin:

| State | Resolution |
|-------|------------|
| Members | Union of both sides |
| Ops/voice | Union (anyone who was op on either side stays op) |
| Bans | Union (all bans apply) |
| Topic | Later `ts` wins |
| Modes | Later `ts` wins |

No "wars" — just merge and move on.

## Deduplication

Servers maintain a rolling window of seen event IDs (recommended: 1 hour or 100,000 events, whichever is larger).

On receiving an event:
1. Check if `@id` is in the seen set
2. If yes, drop silently
3. If no, add to seen set, process, forward to other peers

## Event Retention

Servers should retain events for delta sync. Recommended:
- Minimum: 1 hour
- Maximum: 24 hours (configurable)

Events older than retention window are pruned. Peers requesting events older than the window receive a full sync instead.

## Connection Management

### Reconnection

On disconnect:
1. Wait 5 seconds
2. Reconnect with exponential backoff (5s, 10s, 20s, 40s, max 5 minutes)
3. On success, send `Hello` with current vector
4. Peer responds with `SyncResponse`

### Peer Discovery

On startup and every 5 minutes:
1. Fetch `servers.json` from GitHub
2. Compare to cached version
3. Connect to any new servers
4. Disconnect from any removed servers

## Extensions

Extensions add new contexts and capabilities.

### Capability Negotiation

In `Hello`, servers list supported extensions in `caps`:

```json
"caps": ["delta-sync", "reactions", "threading", "read-receipts"]
```

Only send extension-specific fields to peers that advertise support.

### Example: Reactions Extension

Context at `https://ns.ircd.example/reactions/v1`:

```json
{
  "@context": {
    "@vocab": "https://ns.ircd.example/reactions#",
    "Reaction": "reactions:Reaction",
    "emoji": "reactions:emoji",
    "target": {"@id": "reactions:target", "@type": "@id"}
  }
}
```

Message:

```json
{
  "@context": [
    "https://ns.ircd.example/s2s/v1",
    "https://ns.ircd.example/reactions/v1"
  ],
  "@type": "Reaction",
  "@id": "urn:irc:event:irc.example.com:12390",
  "seq": 12390,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:45:00Z",
  "target": "urn:irc:event:irc.friend.net:8860",
  "from": "urn:irc:user:irc.example.com:alice",
  "emoji": "👍",
  "sig": "...",
  "sigAlg": "ed25519"
}
```

### Example: Threading Extension

Context at `https://ns.ircd.example/threading/v1`:

```json
{
  "@context": {
    "replyTo": {"@id": "https://ns.ircd.example/threading#replyTo", "@type": "@id"},
    "threadRoot": {"@id": "https://ns.ircd.example/threading#threadRoot", "@type": "@id"}
  }
}
```

Add to any message type:

```json
{
  "@context": [
    "https://ns.ircd.example/s2s/v1",
    "https://ns.ircd.example/threading/v1"
  ],
  "@type": "ChannelMessage",
  "@id": "urn:irc:event:irc.example.com:12391",
  "channel": "urn:irc:channel:foo",
  "from": "urn:irc:user:irc.example.com:alice",
  "text": "I agree!",
  "replyTo": "urn:irc:event:irc.friend.net:8855",
  "threadRoot": "urn:irc:event:irc.friend.net:8850",
  ...
}
```

## Security Considerations

1. **Verify all signatures** before processing or forwarding
2. **Verify origin** is in current `servers.json`
3. **Reject seq regressions** (seq going backwards for same origin)
4. **Rate limit** forwarding to prevent amplification attacks
5. **Prune aggressively** to bound memory usage
6. **TLS 1.3 only**, verify peer cert against pubkey in `servers.json`

## Implementation Notes

### Canonical JSON

For signing, produce canonical JSON:
1. Remove `sig` and `sigAlg` fields
2. Serialize with keys sorted lexicographically
3. No whitespace between tokens
4. UTF-8 encoding

Example:
```json
{"@context":"https://ns.ircd.example/s2s/v1","@id":"urn:irc:event:irc.example.com:12345","@type":"Ping","nonce":"abc","origin":"urn:irc:server:irc.example.com","seq":12345,"ts":"2026-08-05T14:00:00Z"}
```

### Event Buffer

Recommended data structure for event retention:
- Ring buffer of events, indexed by `@id`
- Secondary index by `(origin, seq)` for delta sync queries
- Prune by time or count, whichever triggers first

### Vector Clock Storage

Persist vector clock to disk on clean shutdown. On startup:
1. Load persisted vector
2. Fetch `servers.json`
3. Connect to peers
4. Delta sync from persisted vector

If no persisted vector (fresh install), request full sync from first peer.
