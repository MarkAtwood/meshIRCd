# How MeshIRCd Was Vibed

This is the story of a conversation that became a federated IRC server.

## The Prompt

> "do you think you could vibe together a complete and compliant IRC server in go, just using the stdlib and well known packages?"

Yes. Let's find out.

## Day One: The Core

Started with the question of what "compliant" means. Full RFC 1459/2812 is a lot of edge cases. The user's answer:

> "full. but can throw away all the 'old stuff', so TLS only, old modes, stupid ways of doing DCC, etc"

So: modern IRC. No plaintext, no legacy modes, no DCC file transfer. UTF-8 by default. IRCv3 capability negotiation.

Wrote the first version in one file. ~1100 lines. Actor model with goroutine-per-channel. Compiles clean.

Ran code review. Found data races, timing attacks on password comparison, CAP negotiation bugs. Fixed them.

## The Scaling Question

> "irc servers used to bog down because they would overwhelm the select() call and they would do O(N) and O(N^2) scans of tables of every user. is that still a problem?"

No. The historical problems were:
- `select()` is O(n) per call
- Single event loop servicing all connections
- Linear scans through linked lists

Go sidesteps all of this:
- epoll/kqueue under the hood — O(1) for ready fds
- Goroutine per connection — no central bottleneck
- Maps for lookup — O(1) average

> "one goroutine per channel sounds like a lot of goroutines"

It's not. Goroutines are ~2KB, not threads. Production Go runs hundreds of thousands. The server already spawns 2 per client. Channels are cheap.

Refactored to full actor model. Each channel processes events serially in its own goroutine. No mutex needed within the channel.

## Federation: The Design Session

> "it would be neat if this irc server could find its server peers and their keys and other network stuff by checking a github repo and it gets added to a network with a github pr"

Now we're talking.

Walked through the design:
- **Key rotation**: Hard cutover on merge. Coordinate in PR comments.
- **Revocation**: Just delete the entry. Git history preserves who was there.
- **GitHub down**: Fail open with cached config. Log warnings.
- **Verification**: Pubkey only. The key *is* the identity.
- **Polling vs push**: Poll every 5 minutes. Webhooks add complexity for no real gain at hobbyist scale.

> "does irc yet have 'discovery and autonegotiation' of servers?"

No. IRC is from 1988. Clients know where servers are. Modern approaches use DNS SRV records, but that's external to the protocol.

For MeshIRCd: GitHub is the discovery layer. Git is the coordination layer. PRs are the trust decisions.

## The S2S Protocol

> "if we are making up our own s2s protocol, lets do it right and think about it"

Walked through layer by layer:
- **Transport**: TLS 1.3, mutual auth
- **Framing**: Newline-delimited JSON (easy to debug with `openssl s_client | jq`)
- **Message envelope**: ID, Lamport sequence, origin, signature
- **Message types**: Hello, Ping/Pong, UserOnline/Offline, Join/Part, ChannelMessage, etc.
- **State sync**: Delta sync with vector clocks, fall back to full sync if too far behind
- **Deduplication**: Rolling window of seen message IDs

> "can we solve problems with some sort of crypto clock?"

Lamport clocks + signatures. Every event has a sequence number. On receive, bump local clock to `max(local, received) + 1`. Conflicts resolved by `(seq, origin)` tuple — lower wins. Deterministic, no clock sync needed, no NTP trust.

> "i like it. does it break the irc protocol? do we care?"

Two protocols:
- **C2S**: Standard IRC. Clients connect with irssi, weechat, hexchat. They see normal IRC.
- **S2S**: Our thing. JSON-LD, signatures, the works. Clients never see it.

C2S stays IRC. S2S is ours.

## JSON-LD

> "for messages i want them to be that json-xx extensible protocol"

JSON-LD. Full linked data semantics. Context documents define the vocabulary. Extensions bring their own contexts. Unknown fields are preserved and forwarded.

Nailed down the full type vocabulary. Wrote `S2S.md`.

## Identity

> "i want users to be able to annotate themselves with DIDs and other JSON-LD stuff"

Users attach Decentralized Identifiers to their IRC presence:
- `did:key:...` — self-certifying, derived from public key
- `did:web:example.com` — domain-based, server fetches DID document

Challenge-response proof. Server verifies signature. Identity propagates across federation. Shows in WHOIS.

> "why didn't we use METADATA?"

We could have. IRCv3 METADATA is a draft that never got wide adoption. But the user was right — it's cleaner to layer on an existing spec than invent commands.

Revised: `METADATA * SET identity :<json-ld>`. One new command: `IDENTITY CHALLENGE` for the proof nonce. Everything else is standard METADATA.

## IRCv3

> "what else should we steal from IRCv3 for this whole project?"

- **SASL EXTERNAL**: TLS client cert maps to DID. Zero-password auth.
- **message-ids**: Unique ID on every message, matches S2S events.
- **echo-message**: Server confirms your messages.
- **chathistory**: Mobile-friendly scrollback.
- **labeled-response**: Correlate async request/response.

Wrote `IRCV3.md`.

## Implementation

> "ultracode decompose all this implementation work down into beads. then implement it. for every logical chunk of code you create or modify, run /codereview over it 3 times, and work all the resulting beads as well"

Spawned a workflow:
1. Decomposed into 23 beads issues
2. Implemented core: s2s.go, discovery.go, identity.go
3. Reviewed 3x, fixed findings
4. Implemented IRCv3: ircv3.go, chathistory.go
5. Reviewed 3x, fixed findings
6. Implemented federation: federation.go, peer.go
7. Reviewed 3x, fixed findings

53 agents total. 8,042 lines of Go. All issues closed.

> "ultracode do those 5 issues, with the same /codereview discipline"

Another workflow for the remaining identity features. 39 more agents. 33 review findings found and fixed.

## The Name

> "lets pick a name for it. MeshIRC?"

Close.

> "actually, MeshIRCd"

With the 'd' for daemon. Traditional.

## Containerization

> "i want people to be able to just run this containerized"

Added:
- Dockerfile (multi-stage, 15 lines)
- Environment variables: `MESHIRCD_HOSTNAME`, `MESHIRCD_DISCOVERY_URL`, `MESHIRCD_NETWORK`, `MESHIRCD_ADMIN`
- `/data` volume for keys and cache
- Init mode generates keys and outputs servers.json block

The flow: `docker run --init` → PR the output → `docker run` with discovery URL.

## The Network Repo

> "we also need to create a github repo for the meshircd network discovery process"

Created [meshircd-network](https://github.com/MarkAtwood/meshircd-network) — the actual servers.json that servers poll. Join with a PR. Step-by-step instructions in the README.

Two repos now:
- **meshIRCd** — the code
- **meshircd-network** — the network membership

Git as coordination layer, all the way down.

## Running Behind Caddy

> "can this run behind a caddy? because my personal setup is running containers on my homeserver, and using tailscale to get them to a vpc on the internet running caddy"

Yes, with TCP passthrough. TLS terminates at MeshIRCd, not Caddy, so federation peers see the right cert. Caddy's `layer4` plugin routes by SNI without touching the TLS handshake.

One port (6697) for both clients and S2S. Keep it simple.

## What We Built

A federated IRC server that:
- Speaks standard IRC to clients
- Speaks JSON-LD over TLS to peers
- Finds peers via a GitHub repo
- Lets users prove their identity with DIDs
- Orders events with Lamport clocks
- Signs everything with Ed25519
- Heals partitions automatically
- Requires no central coordination

8,042 lines of Go. 4 spec documents. One conversation.

## The Philosophy

Some things that emerged:

**Don't over-engineer.** The first version was one file. Still is, mostly. Split when it hurts.

**Talk before coding.** We spent more time discussing the S2S protocol than implementing it. The implementation was fast because the design was settled.

**Steal good ideas.** IRCv3 METADATA, JSON-LD contexts, Lamport clocks, DIDs. None of these are new. Combining them is.

**Trust the conversation.** The user didn't write a spec doc. They asked questions, I proposed answers, they pushed back, we converged. The spec docs came out of the conversation, not before it.

**Review is part of the work.** Every chunk got 3 code reviews. 33 findings in the identity code alone. Bugs are cheaper to fix when you're looking for them.

**Name it last.** We built the whole thing before picking a name. The name describes what it is, not what we hoped it would be.

## Files

```
meshircd/
├── main.go          # Core IRC server + IRCv3 + identity + flood control
├── s2s.go           # JSON-LD types, Lamport clocks, signatures
├── federation.go    # Peer manager, routing, state sync, network MOTD
├── peer.go          # TLS connections, reconnect
├── discovery.go     # servers.json + motd.txt fetch from GitHub
├── identity.go      # DID parsing, proof verification
├── ircv3.go         # SASL, echo-message, labeled-response
├── chathistory.go   # Message storage, CHATHISTORY commands
├── Dockerfile       # Multi-stage build
├── S2S.md           # Federation protocol spec
├── IDENTITY.md      # DID identity spec
├── IRCV3.md         # IRCv3 extensions spec
├── DISCOVERY.md     # GitHub discovery spec
├── README.md        # What it is
└── VIBED.md         # How it happened

meshircd-network/
├── servers.json     # Network membership (pubkeys, ports, admins)
├── motd.txt         # Network-wide MOTD
└── README.md        # How to join
```

## Day Two: Production

> "ok, look at my ~/.ssh/config and recognize my dokr vm and my caddy vps... i think you also have cli or rest access to my dns provider for reviewcommit.com"

Time to deploy for real. The setup: container on dokr (homeserver), Caddy on joumon (VPS), Tailscale between them, DNS at irc.reviewcommit.com.

Built Caddy with layer4 plugin on joumon for TCP passthrough. TLS terminates at MeshIRCd, not Caddy — peers need to see the right cert.

First connection attempt from macOS Textual: TLS handshake failed. Error -9824.

> "so this is a macos fuckup"

Yes. macOS Secure Transport doesn't support Ed25519 TLS certificates. Only ECDSA and RSA.

Originally used Ed25519 for everything — TLS and federation signing — because it's cleaner. But Apple had other plans.

**Dual-key solution**: ECDSA P-256 for TLS (macOS compatible), Ed25519 for federation signing. Two keys, two purposes.

```go
// runInit now generates both:
// - server.key (ECDSA) + server.crt for TLS
// - fed.key (Ed25519) for federation signing
```

New flag: `--fed-key` for the federation key path.

Federation re-enabled. Clients connect. Done.

## The 482 Bug

> "every time I join a channel, I get 'You're not a channel operator'"

Textual (and irssi) send `MODE #channel b` on join to query the ban list. The server was treating any MODE with letters as a mode change requiring op.

The fix: detect list-only queries (b/e/I without parameters) and return the list instead of 482.

```go
// MODE #channel b   → return ban list (RPL_BANLIST)
// MODE #channel +b *!*@evil.com → requires op
isListQuery := len(params) == 0 && containsOnlyListModes(modeStr)
```

One if statement. Bug gone.

## Quality of Life

> "IP addresses are kinda bullshit in IRC now. maybe everyone is 'cloaked'?"

Yes. Everyone shows `@irc.reviewcommit.com` instead of their IP. One line: set hostname to server name on connect.

> "what are some interesting 'extensions' that irssi does?"

MONITOR, WATCH, AWAY-NOTIFY. Friend online notifications.

> "implement all these"

MONITOR/WATCH: maps on the client, check on connect/disconnect.
AWAY-NOTIFY: broadcast away changes to shared channels.

> "i want a channel named '##' that everyone autojoins on connect"

One line after registration complete: join ##.

> "talk to me about flood control"

Token bucket. 5 messages/second, burst 10. Over limit = silent drop.

```go
// ponytail: token bucket, 15 lines
c.floodTokens += elapsed.Seconds() * 5.0
if c.floodTokens > 10 { c.floodTokens = 10 }
if c.floodTokens < 1 { continue }
c.floodTokens--
```

## Network MOTD

> "yay it works. ok, 'MOTD File is missing'"

Two-level MOTD: network MOTD from the GitHub repo (fetched with discovery), local MOTD from file. Users see both.

```
=== MeshIRCd Network ===
Welcome to MeshIRCd Network
A federated IRC network with no central authority.
...
=== irc.reviewcommit.com ===
[local MOTD if configured]
```

## What's Running

`irc.reviewcommit.com:6697` — the first node.

```
dokr (homeserver)
  └── meshircd container
        ├── ECDSA cert (TLS)
        ├── Ed25519 key (federation)
        └── polls GitHub for peers
              ↓ Tailscale
joumon (VPS)
  └── Caddy layer4
        └── TCP passthrough to dokr
              ↓
Internet (:6697)
```

Connect with any IRC client. Join ##.

## Remaining Work

- **File transfer**: HTTP upload for modern DCC. Beaded, not urgent.

## What We Learned

**Apple breaks everything.** Ed25519 is the right choice for TLS certs. Apple doesn't support it. Now we have two keys.

**List queries aren't mode changes.** IRC protocol quirk from the 80s. MODE can mean "show me" or "change this" depending on parameters.

**Flood control is 15 lines.** Token bucket, stdlib only. Add complexity when someone actually floods you.

**Cloaking is one line.** Set hostname to server name. Done.

**The network repo works.** Servers poll GitHub, find each other, federate. PRs are join requests. Git is the coordination layer.

## License

AGPL-3.0

Because if you run a federated service, your users should be able to see how it works.
