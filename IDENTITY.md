# IRC Identity Extension

Self-sovereign identity for IRC. Users attach DIDs and JSON-LD claims to their presence using IRCv3 METADATA, with a minimal extension for proof challenges.

## Overview

- Identity stored via standard IRCv3 `METADATA` command
- One new command: `IDENTITY CHALLENGE` for proof nonces
- Server verifies proofs, propagates via S2S
- Query via `METADATA GET`, `WHOIS`, or `CTCP METADATA`
- Full JSON-LD, compatible with DIDs, Verifiable Credentials, ActivityPub profiles

## IRCv3 METADATA

This extension builds on the [IRCv3 METADATA draft](https://ircv3.net/specs/extensions/metadata.html).

### Capabilities

```
CAP REQ :metadata identity
```

- `metadata` — IRCv3 METADATA support
- `identity` — this extension (adds IDENTITY CHALLENGE, DID verification)

### Reserved Keys

| Key | Type | Description |
|-----|------|-------------|
| `identity` | JSON-LD | DID document with proof |

## C2S Protocol

### Set Identity

```
METADATA * SET identity :{"@context":[...],"id":"did:key:...","proof":{...}}
```

Server parses, verifies proof, stores. Standard METADATA response:

```
:server METADATA * identity * :{"@context":[...],"id":"did:key:...","proof":{...}}
```

On verification failure:

```
:server FAIL METADATA INVALID_VALUE identity :Signature verification failed
```

### Get Identity

Own identity:
```
METADATA * GET identity
```

Other user's identity:
```
METADATA bob GET identity
```

Response:
```
:server METADATA bob identity * :{"@context":[...],"id":"did:key:..."}
```

Or if none set:
```
:server METADATA bob identity * :
```

### Clear Identity

```
METADATA * CLEAR identity
```

Response:
```
:server METADATA * identity * :
```

### List Metadata

```
METADATA bob LIST
```

Shows all public metadata keys including `identity`.

### Request Challenge

The one command we add beyond METADATA:

```
IDENTITY CHALLENGE
```

Response:
```
:server 903 alice :irc:alice@irc.example.com:1722870000
```

Challenge format: `irc:<nick>@<server>:<unix-timestamp>`. Valid for 5 minutes.

Numeric 903 `RPL_IDENTITYCHALLENGE`.

### METADATA Notifications

When a user's identity changes, servers broadcast per METADATA spec:

```
:server METADATA bob identity * :{"@context":[...],"id":"did:key:..."}
```

Clients subscribed to metadata updates receive this.

## Identity Document Structure

### Minimal Identity

Just a DID with proof of control:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://ns.ircd.example/identity/v1"
  ],
  "id": "did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-08-05T14:00:00Z",
    "verificationMethod": "did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4#key-1",
    "challenge": "irc:alice@irc.example.com:1722870000",
    "proofPurpose": "authentication",
    "proofValue": "z..."
  }
}
```

### Extended Identity

Links to other profiles, keys, claims:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://www.w3.org/2018/credentials/v1",
    "https://ns.ircd.example/identity/v1",
    "https://w3id.org/security/v2"
  ],
  "id": "did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4",
  
  "alsoKnownAs": [
    "did:web:bob.example",
    "did:plc:abc123...",
    "https://mastodon.social/@bob",
    "https://bsky.app/profile/bob.example"
  ],
  
  "publicKey": [
    {
      "id": "did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4",
      "publicKeyMultibase": "z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4"
    }
  ],
  
  "service": [
    {
      "id": "did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4#homepage",
      "type": "LinkedDomains",
      "serviceEndpoint": "https://bob.example"
    }
  ],
  
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-08-05T14:00:00Z",
    "verificationMethod": "did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4#key-1",
    "challenge": "irc:alice@irc.example.com:1722870000",
    "proofPurpose": "authentication",
    "proofValue": "z..."
  }
}
```

### Verifiable Credentials

Users can attach VCs issued by others:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://www.w3.org/2018/credentials/v1",
    "https://ns.ircd.example/identity/v1"
  ],
  "id": "did:key:z6Mk...",
  
  "verifiableCredential": [
    {
      "@context": "https://www.w3.org/2018/credentials/v1",
      "type": ["VerifiableCredential", "EmailCredential"],
      "issuer": "did:web:verify.example",
      "issuanceDate": "2026-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:key:z6Mk...",
        "email": "bob@example.com",
        "verified": true
      },
      "proof": {
        "type": "Ed25519Signature2020",
        "verificationMethod": "did:web:verify.example#key-1",
        "proofValue": "z..."
      }
    }
  ],
  
  "proof": { ... }
}
```

## Identity Context

Context document at `https://ns.ircd.example/identity/v1`:

```json
{
  "@context": {
    "@version": 1.1,
    "@vocab": "https://ns.ircd.example/identity#",
    
    "irc": "https://ns.ircd.example/irc#",
    "did": "https://www.w3.org/ns/did#",
    "sec": "https://w3id.org/security#",
    "cred": "https://www.w3.org/2018/credentials#",
    
    "id": "@id",
    "type": "@type",
    
    "IRCIdentity": "irc:Identity",
    "nick": "irc:nickname",
    "server": {"@id": "irc:server", "@type": "@id"},
    "network": "irc:network",
    "verified": {"@id": "irc:verified", "@type": "xsd:boolean"},
    "verifiedAt": {"@id": "irc:verifiedAt", "@type": "xsd:dateTime"},
    
    "alsoKnownAs": {"@id": "https://www.w3.org/ns/activitystreams#alsoKnownAs", "@type": "@id", "@container": "@set"},
    "publicKey": {"@id": "sec:publicKey", "@container": "@set"},
    "service": {"@id": "did:service", "@container": "@set"},
    "verifiableCredential": {"@id": "cred:verifiableCredential", "@container": "@set"},
    
    "proof": "sec:proof"
  }
}
```

## Proof Verification

### Challenge-Response Flow

1. Client requests challenge:
   ```
   IDENTITY CHALLENGE
   ```

2. Server responds:
   ```
   :server 903 alice :irc:alice@irc.example.com:1722870000
   ```

3. Client signs challenge with DID key, constructs identity document with proof

4. Client submits via METADATA:
   ```
   METADATA * SET identity :<json-ld with proof>
   ```

5. Server verifies:
   - Parse JSON-LD
   - Extract DID from `id` field
   - Resolve DID document (fetch `did:web:`, derive `did:key:`, etc.)
   - Extract verification method
   - Verify signature over challenge
   - Check challenge is recent (< 5 minutes) and matches current nick@server
   - Store identity
   - Broadcast METADATA notification

### Supported DID Methods

Servers MUST support:
- `did:key` — self-certifying, derived from public key, no resolution needed

Servers SHOULD support:
- `did:web` — fetch `/.well-known/did.json` from domain

Servers MAY support:
- `did:plc` — Bluesky's DID method
- `did:pkh` — blockchain address based
- Others as extensions

### Signature Types

Servers MUST support:
- `Ed25519Signature2020`

Servers MAY support:
- `EcdsaSecp256k1Signature2019`
- `JsonWebSignature2020`

## S2S Protocol

### Identity Event

When a user sets or clears identity, propagate via S2S:

```json
{
  "@context": [
    "https://ns.ircd.example/s2s/v1",
    "https://ns.ircd.example/identity/v1"
  ],
  "@type": "IdentityUpdate",
  "@id": "urn:irc:event:irc.example.com:12400",
  "seq": 12400,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:05:00Z",
  
  "user": "urn:irc:user:irc.example.com:alice",
  "identity": {
    "@context": [...],
    "id": "did:key:z6Mk...",
    "proof": {...}
  },
  
  "sig": "...",
  "sigAlg": "ed25519"
}
```

For identity clear:

```json
{
  "@context": "https://ns.ircd.example/s2s/v1",
  "@type": "IdentityUpdate",
  "@id": "urn:irc:event:irc.example.com:12401",
  "seq": 12401,
  "origin": "urn:irc:server:irc.example.com",
  "ts": "2026-08-05T14:06:00Z",
  
  "user": "urn:irc:user:irc.example.com:alice",
  "identity": null,
  
  "sig": "...",
  "sigAlg": "ed25519"
}
```

### Sync

Identity is included in full sync as part of user objects:

```json
{
  "@type": "SyncResponse",
  "users": [
    {
      "@type": "User",
      "@id": "urn:irc:user:irc.example.com:alice",
      "nick": "alice",
      "ident": "alice",
      "host": "...",
      "realname": "...",
      "identity": {
        "id": "did:key:z6Mk...",
        "proof": {...}
      }
    }
  ]
}
```

### Cross-Server Verification

Receiving servers SHOULD re-verify proofs before accepting. Challenge format includes originating server, so verify:
1. Proof is valid signature
2. Challenge server matches `origin` of the S2S event
3. Challenge nick matches user nick at time of signing

Servers MAY trust origin server's verification and skip re-verification (tradeoff: less work, more trust).

## WHOIS Integration

When a user has identity set, WHOIS includes it:

```
/whois bob
```

```
:server 311 alice bob ~bob host.example.com * :Bob Smith
:server 320 alice bob :DID did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4
:server 320 alice bob :Verified true
:server 320 alice bob :AKA https://mastodon.social/@bob
:server 320 alice bob :Homepage https://bob.example
:server 312 alice bob irc.example.com :Example IRC
:server 318 alice bob :End of /WHOIS list
```

WHOIS formatting extracts key fields:

| Field | WHOIS Line |
|-------|------------|
| `id` | `DID <did-uri>` |
| Verification status | `Verified true/false` |
| `alsoKnownAs[*]` | `AKA <uri>` (one per line) |
| `service[type=LinkedDomains]` | `Homepage <url>` |
| Email VC | `Email <email> (verified by <issuer>)` |

## Client Implementation Guide

### Any IRC Client (No Special Support)

Request challenge:
```
/quote IDENTITY CHALLENGE
```

Note the response. Use external tool to sign:
```bash
did-sign --did did:key:z6Mk... --challenge "irc:alice@irc.example.com:1722870000"
```

Set identity:
```
/quote METADATA * SET identity :{"@context":[...],"id":"did:key:...","proof":{...}}
```

Query others:
```
/quote METADATA bob GET identity
/whois bob
```

Clear:
```
/quote METADATA * CLEAR identity
```

### Clients With METADATA Support

Some clients (e.g., some builds of irssi, weechat scripts) support METADATA natively:

```
/metadata set identity <json-ld>
/metadata get bob identity
```

### Enhanced Clients

Clients MAY implement:
- Key management (generate, store, sign)
- Automatic challenge-response flow
- Identity badge display next to nicks
- Click-to-verify proof checking
- DID resolution and display

## Security Considerations

1. **Challenge freshness** — Reject challenges older than 5 minutes
2. **Challenge binding** — Challenge includes nick and server, preventing replay across contexts
3. **DID resolution** — `did:web` requires HTTPS fetch; cache but respect TTL
4. **VC issuer trust** — Displaying VCs doesn't imply trusting issuers; UI should distinguish
5. **Privacy** — Identity is public to the network; don't attach sensitive claims
6. **Key compromise** — If DID key is compromised, user must clear and re-establish with new DID
7. **METADATA visibility** — The `identity` key is public; servers MUST NOT allow setting it as private

## Relationship to IRCv3 METADATA

This extension is a profile of IRCv3 METADATA:

| IRCv3 METADATA | This Extension |
|----------------|----------------|
| Arbitrary keys | `identity` key reserved |
| String values | JSON-LD value |
| No validation | Server verifies proofs |
| Standard notifications | Plus S2S IdentityUpdate |

Servers implementing this extension MUST also implement base METADATA semantics for the `identity` key. Other METADATA keys are unaffected.

## Examples

### did:key (Self-Certifying)

Simplest case. DID is derived from public key, no resolution needed.

```
/quote IDENTITY CHALLENGE
```
```
:server 903 alice :irc:alice@irc.example.com:1722870000
```

```
/quote METADATA * SET identity :{"@context":["https://www.w3.org/ns/did/v1","https://ns.ircd.example/identity/v1"],"id":"did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4","proof":{"type":"Ed25519Signature2020","created":"2026-08-05T14:00:00Z","verificationMethod":"did:key:z6MkhaXgBZDvotDUSSc9MQVg39RKGHVx9zjSFMTTxJfNsJT4#key-1","challenge":"irc:alice@irc.example.com:1722870000","proofPurpose":"authentication","proofValue":"zBase64Signature..."}}
```

### did:web (Domain-Based)

Prove you control a domain. Server fetches `https://bob.example/.well-known/did.json`.

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://ns.ircd.example/identity/v1"],
  "id": "did:web:bob.example",
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:bob.example#key-1",
    "challenge": "irc:bob@irc.example.com:1722870000",
    "proofValue": "z..."
  }
}
```

### Linking Multiple Identities

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://ns.ircd.example/identity/v1"],
  "id": "did:key:z6Mk...",
  "alsoKnownAs": [
    "did:web:bob.example",
    "did:plc:abc123",
    "at://bob.example",
    "https://github.com/bob",
    "https://mastodon.social/@bob"
  ],
  "proof": {...}
}
```

Note: `alsoKnownAs` claims are self-asserted. For bidirectional proof, the linked profile should link back (e.g., GitHub bio contains DID).
