# IRCv3 Extensions

IRCv3 specifications adopted for this server, with integration notes for federation and identity.

## Capabilities

Full capability list advertised by server:

```
CAP LS 302
:server CAP * LS :account-notify account-tag away-notify batch cap-notify chghost echo-message extended-join invite-notify labeled-response message-ids message-tags metadata multi-prefix sasl=EXTERNAL,PLAIN server-time setname draft/chathistory identity
```

| Capability | Spec | Notes |
|------------|------|-------|
| `account-notify` | IRCv3 | Notify when user logs in/out |
| `account-tag` | IRCv3 | `@account=` on messages |
| `away-notify` | IRCv3 | Notify when user goes away |
| `batch` | IRCv3 | Group related messages |
| `cap-notify` | IRCv3 | Notify on cap changes |
| `chghost` | IRCv3 | Notify on host change |
| `echo-message` | IRCv3 | Echo own messages back |
| `extended-join` | IRCv3 | JOIN includes account/realname |
| `invite-notify` | IRCv3 | Channel sees invites |
| `labeled-response` | IRCv3 | Correlate request/response |
| `message-ids` | IRCv3 | `@msgid=` on messages |
| `message-tags` | IRCv3 | Arbitrary message tags |
| `metadata` | IRCv3 draft | Key-value storage |
| `multi-prefix` | IRCv3 | All prefixes in NAMES/WHO |
| `sasl` | IRCv3 | Auth mechanism |
| `server-time` | IRCv3 | `@time=` on messages |
| `setname` | IRCv3 | Change realname |
| `draft/chathistory` | IRCv3 draft | Message history |
| `identity` | This project | DID-based identity |

## SASL Authentication

### Overview

SASL replaces `PASS` with proper authentication. We support:

- **EXTERNAL** — TLS client certificate, maps to DID
- **PLAIN** — Username/password fallback

### EXTERNAL (Preferred)

Client presents TLS cert during handshake. Cert public key maps to a `did:key`.

Flow:
```
Client                              Server
  |                                    |
  |------- TLS handshake + cert ------>|
  |                                    |
  |  CAP REQ :sasl                     |
  |------------------------------>>    |
  |    <<------------------------------| 
  |  CAP ACK :sasl                     |
  |                                    |
  |  AUTHENTICATE EXTERNAL             |
  |------------------------------>>    |
  |    <<------------------------------|
  |  AUTHENTICATE +                    |
  |                                    |
  |  AUTHENTICATE +                    |
  |------------------------------>>    |
  |    <<------------------------------|
  |  903 :SASL auth successful         |
  |                                    |
  |  CAP END                           |
  |------------------------------>>    |
```

Server extracts public key from client cert, derives `did:key`, checks if any registered user has this DID in their identity. If match, auto-login.

### PLAIN (Fallback)

Traditional username:password. Base64 encoded.

```
AUTHENTICATE PLAIN
AUTHENTICATE AGFsaWNlAHNlY3JldA==
```

Decoded: `\0alice\0secret`

Server verifies against stored credentials. Consider this legacy — prefer EXTERNAL + DID.

### Account Registration

New accounts can be created via:

1. **DID-first**: Set identity via METADATA, that creates the account
2. **Traditional**: REGISTER command (if implemented)

With DID-first, there's no password. Auth is always via EXTERNAL.

### Numerics

| Numeric | Name | Description |
|---------|------|-------------|
| 900 | RPL_LOGGEDIN | `<nick>!<user>@<host> <account> :You are now logged in as <account>` |
| 901 | RPL_LOGGEDOUT | `:You are now logged out` |
| 902 | ERR_NICKLOCKED | `:You must use a nick assigned to you` |
| 903 | RPL_SASLSUCCESS | `:SASL authentication successful` |
| 904 | ERR_SASLFAIL | `:SASL authentication failed` |
| 905 | ERR_SASLTOOLONG | `:SASL message too long` |
| 906 | ERR_SASLABORTED | `:SASL authentication aborted` |
| 907 | ERR_SASLALREADY | `:You have already authenticated` |
| 908 | RPL_SASLMECHS | `<mechs> :are available SASL mechanisms` |

### Integration with Identity

When authenticated via EXTERNAL:
- Server derives `did:key` from cert
- Looks up identity with matching DID
- Sets account name to nick associated with that identity
- `@account=` tag uses nick, `@did=` tag (extension) uses full DID

## Message IDs

### Format

Every message gets a unique ID:

```
@msgid=<server>/<sequence> PRIVMSG #foo :hello
```

Example:
```
@msgid=irc.example.com/12345 :alice!~alice@host PRIVMSG #foo :hello
```

Format: `<origin-server>/<lamport-seq>`

This matches our S2S event IDs, making messages traceable across federation.

### Client Usage

Clients use msgid for:
- Deduplication
- Threading/replies (`+draft/reply` tag)
- Reactions (reference target message)
- Read markers
- Chathistory pagination

### S2S Mapping

C2S `@msgid=irc.example.com/12345` corresponds to S2S event `urn:irc:event:irc.example.com:12345`.

Same ID, different format (bare vs URN).

## Echo-Message

### Overview

Server echoes client's own messages back to them. Client treats server as source of truth.

### Capability

```
CAP REQ :echo-message
```

### Behavior

Without echo-message:
```
Client                              Server
  |  PRIVMSG #foo :hello              |
  |------------------------------>>   |
  |  (nothing back)                   |
```

With echo-message:
```
Client                              Server
  |  PRIVMSG #foo :hello              |
  |------------------------------>>   |
  |   <<------------------------------|
  |  @msgid=.../123 :alice PRIVMSG #foo :hello
```

### Benefits

1. **Message ID assignment** — client learns the msgid
2. **Confirmation** — message was accepted
3. **Timestamp** — server-authoritative time
4. **Consistency** — client can use same code path for own and others' messages

### With labeled-response

```
@label=abc123 PRIVMSG #foo :hello
```

Response:
```
@label=abc123;msgid=irc.example.com/12345 :alice!~alice@host PRIVMSG #foo :hello
```

Client correlates by label.

## Chathistory

### Overview

Request message history for channels and DMs. Essential for mobile/web clients.

### Capability

```
CAP REQ :draft/chathistory
```

### Commands

#### CHATHISTORY LATEST

Get most recent messages:

```
CHATHISTORY LATEST #foo * 50
```

Parameters:
- Target: `#foo` or nick
- Reference: `*` (none) or `msgid=xxx`
- Count: max messages to return

#### CHATHISTORY BEFORE

Get messages before a reference point:

```
CHATHISTORY BEFORE #foo msgid=irc.example.com/12345 50
```

#### CHATHISTORY AFTER

Get messages after a reference point:

```
CHATHISTORY AFTER #foo msgid=irc.example.com/12345 50
```

#### CHATHISTORY AROUND

Get messages around a reference point:

```
CHATHISTORY AROUND #foo msgid=irc.example.com/12345 50
```

#### CHATHISTORY BETWEEN

Get messages between two points:

```
CHATHISTORY BETWEEN #foo timestamp=2026-08-05T00:00:00Z timestamp=2026-08-05T12:00:00Z 100
```

### Targets

Clients can request history for:
- `#channel` — channel messages (must be member or have permission)
- `nick` — DM history with that nick
- `*` — all DM history (aggregated)

### Response Format

History is returned in a batch:

```
:server BATCH +historyBatch chathistory #foo
@batch=historyBatch;msgid=.../100;time=2026-08-05T10:00:00Z :alice PRIVMSG #foo :older message
@batch=historyBatch;msgid=.../101;time=2026-08-05T10:01:00Z :bob PRIVMSG #foo :another message
@batch=historyBatch;msgid=.../102;time=2026-08-05T10:02:00Z :alice PRIVMSG #foo :newer message
:server BATCH -historyBatch
```

### Limits

Server MAY impose limits:
- Max messages per request (e.g., 500)
- Max history retention (e.g., 7 days)
- Rate limiting

Advertise via ISUPPORT:
```
:server 005 alice CHATHISTORY=500 :are supported
```

### S2S Considerations

Chathistory requests for channels with remote users:
- Server has local event log from S2S sync
- Query local log, no need to contact origin
- If event was pruned, cannot retrieve (history is best-effort)

For DMs with remote users:
- Local server stores relayed messages
- Query local log

## Batch

### Overview

Group related messages under a batch ID. Used by chathistory, netjoin/netsplit, and other bulk operations.

### Types

| Type | Usage |
|------|-------|
| `chathistory` | History playback |
| `netjoin` | Users joining after netsplit heals |
| `netsplit` | Users quitting due to netsplit |
| `draft/multiline` | Multi-line message |

### Format

Start batch:
```
:server BATCH +<id> <type> [params...]
```

Messages in batch include `@batch=<id>`:
```
@batch=<id> :alice PRIVMSG #foo :message
```

End batch:
```
:server BATCH -<id>
```

### Nesting

Batches can nest. Inner batch references outer:
```
:server BATCH +outer netjoin #foo
:server BATCH +inner chathistory #foo
@batch=inner :alice PRIVMSG #foo :old message
:server BATCH -inner
@batch=outer :alice!~alice@host JOIN #foo
:server BATCH -outer
```

## Labeled-Response

### Overview

Client tags request with `@label=`, server echoes it on response. Correlates async request/response.

### Usage

```
@label=pqr123 WHOIS bob
```

Response:
```
@label=pqr123 :server 311 alice bob ~bob host * :Bob Smith
@label=pqr123 :server 318 alice bob :End of /WHOIS list
```

### ACK for No Response

If command produces no response (e.g., PING), server sends ACK:

```
@label=xyz789 PING foo
```

```
@label=xyz789 :server ACK
```

### Batch Responses

If response is a batch, label goes on BATCH start:

```
@label=abc CHATHISTORY LATEST #foo * 10
```

```
@label=abc :server BATCH +hist chathistory #foo
@batch=hist :alice PRIVMSG #foo :message
:server BATCH -hist
```

## Account-Tag

### Standard

Messages include `@account=` with sender's account name:

```
@account=alice :alice!~alice@host PRIVMSG #foo :hello
```

If user not logged in, tag is omitted.

### DID Extension

We extend with `@did=` tag:

```
@account=alice;did=did:key:z6Mk... :alice!~alice@host PRIVMSG #foo :hello
```

Requires `identity` capability. Tag present only if sender has verified identity.

Clients can verify:
- `@account` = human-readable nick
- `@did` = cryptographic identity (can be resolved/verified)

## Server-Time

### Format

All messages include `@time=` with ISO 8601 timestamp:

```
@time=2026-08-05T14:30:00.000Z :alice PRIVMSG #foo :hello
```

Server-authoritative time. Clients SHOULD use this for display, not local time.

### Precision

Millisecond precision recommended. Minimum: second precision.

## Extended-Join

### Standard JOIN

```
:alice!~alice@host JOIN #foo
```

### Extended JOIN

With `extended-join` capability:

```
:alice!~alice@host JOIN #foo alice :Alice Smith
```

Format: `JOIN <channel> <account> :<realname>`

If no account: `JOIN #foo * :Alice Smith`

### With Identity

We further extend:

```
:alice!~alice@host JOIN #foo alice :Alice Smith
@did=did:key:z6Mk...
```

The DID is included as a message tag if user has verified identity.

## Setname

### Command

Change realname without reconnecting:

```
SETNAME :New Real Name
```

### Notification

Users sharing channels see:

```
:alice!~alice@host SETNAME :New Real Name
```

Requires `setname` capability to receive notifications.

## Chghost

### Notification

When user's ident or host changes:

```
:alice!~olduser@old.host CHGHOST newuser new.host
```

Requires `chghost` capability.

### Use Cases

- Cloak applied after auth
- Host hidden after oper-up
- Ident changed via SETIDENT (if supported)

## Invite-Notify

### Notification

When someone is invited to a channel you're in:

```
:alice!~alice@host INVITE bob #foo
```

Sent to all channel members with `invite-notify` capability.

## Away-Notify

### Notification

When user in shared channel goes away:

```
:alice!~alice@host AWAY :Gone for lunch
```

When they return:

```
:alice!~alice@host AWAY
```

(Empty AWAY = returned)

## Integration Summary

### C2S to S2S Mapping

| C2S | S2S |
|-----|-----|
| `@msgid=server/123` | `@id: urn:irc:event:server:123` |
| `@time=2026-08-05T...` | `ts: 2026-08-05T...` |
| `@account=alice` | `from: urn:irc:user:server:alice` |
| `@did=did:key:...` | `identity.id: did:key:...` |
| `BATCH` | `events: [...]` in SyncResponse |

### Auth Flow with DID

1. Client connects with TLS cert containing Ed25519 pubkey
2. Client sends `CAP REQ :sasl identity`
3. Client sends `AUTHENTICATE EXTERNAL`
4. Server derives `did:key` from cert pubkey
5. Server looks up identity matching that DID
6. If found: `903 :SASL authentication successful`
7. Client is now logged in as the associated nick
8. `@account=` and `@did=` tags on their messages

### Message Lifecycle

1. Client sends: `@label=abc PRIVMSG #foo :hello`
2. Server assigns msgid, timestamp
3. Server echoes: `@label=abc;msgid=irc.example.com/12345;time=2026-08-05T14:30:00Z :alice!~alice@host PRIVMSG #foo :hello`
4. Server broadcasts to channel (minus label): `@msgid=...;time=...;account=alice;did=did:key:... :alice PRIVMSG #foo :hello`
5. Server creates S2S event with same seq number
6. Federated servers receive and relay to their local clients
7. Message stored in chathistory log

## Implementation Checklist

### Required

- [ ] CAP negotiation (302)
- [ ] message-tags parsing/sending
- [ ] server-time on all messages
- [ ] message-ids on all messages
- [ ] SASL EXTERNAL
- [ ] echo-message

### Recommended

- [ ] chathistory + batch
- [ ] labeled-response
- [ ] account-tag + did extension
- [ ] extended-join

### Optional

- [ ] SASL PLAIN
- [ ] setname
- [ ] chghost
- [ ] invite-notify
- [ ] away-notify
- [ ] multi-prefix
