package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// S2S protocol constants
const (
	S2SContextURL = "https://ns.ircd.example/s2s/v1"
	SigAlgEd25519 = "ed25519"

	// Deduplication window
	DedupeMaxEvents  = 100000
	DedupeMaxAge     = time.Hour
	PingInterval     = 30 * time.Second
	PongTimeout      = 10 * time.Second
	EventRetention   = 24 * time.Hour
	ReconnectInitial = 5 * time.Second
	ReconnectMax     = 5 * time.Minute
)

// S2S message types
const (
	TypeHello          = "Hello"
	TypePing           = "Ping"
	TypePong           = "Pong"
	TypeUserOnline     = "UserOnline"
	TypeUserOffline    = "UserOffline"
	TypeNickChange     = "NickChange"
	TypeJoin           = "Join"
	TypePart           = "Part"
	TypeKick           = "Kick"
	TypeMode           = "Mode"
	TypeTopic          = "Topic"
	TypeChannelMessage = "ChannelMessage"
	TypePrivateMessage = "PrivateMessage"
	TypeNotice         = "Notice"
	TypeSyncRequest    = "SyncRequest"
	TypeSyncResponse   = "SyncResponse"
	TypeIdentityUpdate = "IdentityUpdate"
	TypeError          = "Error"
)

// Error codes
const (
	ErrInvalidSignature = "INVALID_SIGNATURE"
	ErrUnknownOrigin    = "UNKNOWN_ORIGIN"
	ErrSeqRegression    = "SEQ_REGRESSION"
	ErrUnknownType      = "UNKNOWN_TYPE"
	ErrMalformed        = "MALFORMED"
	ErrSyncTooOld       = "SYNC_TOO_OLD"
)

// Envelope is the common structure for all S2S messages
type Envelope struct {
	Context  interface{} `json:"@context"`
	Type     string      `json:"@type"`
	ID       string      `json:"@id"`
	Seq      int64       `json:"seq"`
	Origin   string      `json:"origin"`
	Ts       string      `json:"ts"`
	Sig      string      `json:"sig,omitempty"`
	SigAlg   string      `json:"sigAlg,omitempty"`

	// Payload fields (varies by type)
	Payload map[string]interface{} `json:"-"`
}

// MarshalJSON handles envelope serialization with payload fields at top level
func (e *Envelope) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["@context"] = e.Context
	m["@type"] = e.Type
	m["@id"] = e.ID
	m["seq"] = e.Seq
	m["origin"] = e.Origin
	m["ts"] = e.Ts
	if e.Sig != "" {
		m["sig"] = e.Sig
		m["sigAlg"] = e.SigAlg
	}
	for k, v := range e.Payload {
		m[k] = v
	}
	return json.Marshal(m)
}

// UnmarshalJSON handles envelope deserialization, extracting payload fields
func (e *Envelope) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	if ctx, ok := m["@context"]; ok {
		e.Context = ctx
	}
	if t, ok := m["@type"].(string); ok {
		e.Type = t
	}
	if id, ok := m["@id"].(string); ok {
		e.ID = id
	}
	if seq, ok := m["seq"].(float64); ok {
		e.Seq = int64(seq)
	}
	if origin, ok := m["origin"].(string); ok {
		e.Origin = origin
	}
	if ts, ok := m["ts"].(string); ok {
		e.Ts = ts
	}
	if sig, ok := m["sig"].(string); ok {
		e.Sig = sig
	}
	if sigAlg, ok := m["sigAlg"].(string); ok {
		e.SigAlg = sigAlg
	}

	// Remaining fields go to payload
	e.Payload = make(map[string]interface{})
	for k, v := range m {
		switch k {
		case "@context", "@type", "@id", "seq", "origin", "ts", "sig", "sigAlg":
			continue
		default:
			e.Payload[k] = v
		}
	}
	return nil
}

// Hello message sent after TLS handshake
type Hello struct {
	Envelope
	Caps   []string         `json:"caps"`
	Vector map[string]int64 `json:"vector"`
}

// Ping keepalive message
type Ping struct {
	Envelope
	Nonce string `json:"nonce"`
}

// Pong keepalive response
type Pong struct {
	Envelope
	Nonce string `json:"nonce"`
}

// User represents user data in S2S messages
type User struct {
	Type     string `json:"@type,omitempty"`
	ID       string `json:"@id"`
	Nick     string `json:"nick"`
	Ident    string `json:"ident"`
	Host     string `json:"host"`
	Realname string `json:"realname"`
}

// UserOnline indicates a user connected
type UserOnline struct {
	Envelope
	User User `json:"user"`
}

// UserOffline indicates a user disconnected
type UserOffline struct {
	Envelope
	User   string `json:"user"`
	Reason string `json:"reason,omitempty"`
}

// NickChange indicates a user changed nickname
type NickChange struct {
	Envelope
	User    string `json:"user"`
	OldNick string `json:"oldNick"`
	NewNick string `json:"newNick"`
}

// Join indicates a user joined a channel
type Join struct {
	Envelope
	User    string `json:"user"`
	Channel string `json:"channel"`
	Modes   string `json:"modes,omitempty"`
}

// Part indicates a user left a channel
type Part struct {
	Envelope
	User    string `json:"user"`
	Channel string `json:"channel"`
	Reason  string `json:"reason,omitempty"`
}

// Kick indicates a user was kicked from a channel
type Kick struct {
	Envelope
	Channel string `json:"channel"`
	User    string `json:"user"`
	By      string `json:"by"`
	Reason  string `json:"reason,omitempty"`
}

// Mode indicates a channel or user mode change
type Mode struct {
	Envelope
	Channel string `json:"channel,omitempty"`
	User    string `json:"user,omitempty"`
	By      string `json:"by,omitempty"`
	Changes string `json:"changes"`
}

// Topic indicates a channel topic change
type Topic struct {
	Envelope
	Channel string `json:"channel"`
	By      string `json:"by"`
	Topic   string `json:"topic"`
}

// ChannelMessage is a PRIVMSG to a channel
type ChannelMessage struct {
	Envelope
	Channel string `json:"channel"`
	From    string `json:"from"`
	Text    string `json:"text"`
}

// PrivateMessage is a direct message between users
type PrivateMessage struct {
	Envelope
	From string `json:"from"`
	To   string `json:"to"`
	Text string `json:"text"`
}

// Notice is like ChannelMessage/PrivateMessage but should not trigger auto-replies
type Notice struct {
	Envelope
	Channel string `json:"channel,omitempty"`
	From    string `json:"from"`
	To      string `json:"to,omitempty"`
	Text    string `json:"text"`
}

// SyncRequest requests missing events based on vector clock
type SyncRequest struct {
	Envelope
	Vector map[string]int64 `json:"vector"`
}

// ChannelMember represents a user in a channel with their modes
type ChannelMember struct {
	User  string `json:"user"`
	Modes string `json:"modes"`
}

// Ban represents a channel ban
type Ban struct {
	Mask string `json:"mask"`
	By   string `json:"by"`
	Ts   string `json:"ts"`
}

// ChannelState represents full channel state in sync response
type ChannelState struct {
	Type     string          `json:"@type"`
	ID       string          `json:"@id"`
	Topic    string          `json:"topic,omitempty"`
	TopicBy  string          `json:"topicBy,omitempty"`
	TopicTs  string          `json:"topicTs,omitempty"`
	Modes    string          `json:"modes"`
	Members  []ChannelMember `json:"members"`
	Bans     []Ban           `json:"bans,omitempty"`
}

// SyncResponse contains events the peer is missing
type SyncResponse struct {
	Envelope
	Events   []json.RawMessage `json:"events,omitempty"`
	FullSync bool              `json:"fullSync,omitempty"`
	Users    []User            `json:"users,omitempty"`
	Channels []ChannelState    `json:"channels,omitempty"`
}

// IdentityUpdate propagates identity changes via S2S
type IdentityUpdate struct {
	Envelope
	User     string      `json:"user"`
	Identity interface{} `json:"identity"` // null to clear
}

// Error indicates a protocol or processing error
type Error struct {
	Envelope
	Code    string `json:"code"`
	Message string `json:"message"`
	Ref     string `json:"ref,omitempty"`
}

// LamportClock tracks logical time for event ordering
type LamportClock struct {
	mu     sync.Mutex
	seq    int64
	vector map[string]int64 // server URN -> last seen seq
}

// NewLamportClock creates a new Lamport clock
func NewLamportClock() *LamportClock {
	return &LamportClock{
		seq:    0,
		vector: make(map[string]int64),
	}
}

// Next increments and returns the next sequence number
func (lc *LamportClock) Next() int64 {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.seq++
	return lc.seq
}

// Current returns the current sequence number without incrementing
func (lc *LamportClock) Current() int64 {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.seq
}

// Merge updates the clock based on a received event
// local_seq = max(local_seq, event.seq) + 1
// vector[event.origin] = max(vector[event.origin], event.seq)
func (lc *LamportClock) Merge(origin string, eventSeq int64) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if eventSeq > lc.seq {
		lc.seq = eventSeq
	}
	lc.seq++

	if eventSeq > lc.vector[origin] {
		lc.vector[origin] = eventSeq
	}
}

// GetVector returns a copy of the current vector clock
func (lc *LamportClock) GetVector() map[string]int64 {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	v := make(map[string]int64, len(lc.vector))
	for k, val := range lc.vector {
		v[k] = val
	}
	return v
}

// SetVector updates vector entries without advancing local seq
func (lc *LamportClock) SetVector(origin string, seq int64) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if seq > lc.vector[origin] {
		lc.vector[origin] = seq
	}
}

// Compare returns -1 if (seqA, originA) < (seqB, originB), 0 if equal, 1 if greater
// Used for deterministic conflict resolution (lower tuple wins)
func Compare(seqA int64, originA string, seqB int64, originB string) int {
	if seqA < seqB {
		return -1
	}
	if seqA > seqB {
		return 1
	}
	// Same seq, compare origins lexicographically
	if originA < originB {
		return -1
	}
	if originA > originB {
		return 1
	}
	return 0
}

// CanonicalJSON produces canonical JSON for signing:
// - Keys sorted lexicographically
// - No whitespace between tokens
// - UTF-8 encoding
func CanonicalJSON(v interface{}) ([]byte, error) {
	// Marshal to map first to handle field removal and sorting
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	// Remove sig and sigAlg for signing
	delete(m, "sig")
	delete(m, "sigAlg")

	return canonicalizeMap(m)
}

// canonicalizeMap produces canonical JSON from a map with sorted keys
func canonicalizeMap(m map[string]interface{}) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')

	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}

		// Write key
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')

		// Write value
		valBytes, err := canonicalizeValue(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}

	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// canonicalizeValue produces canonical JSON for any value
func canonicalizeValue(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		return canonicalizeMap(val)
	case []interface{}:
		return canonicalizeArray(val)
	default:
		// Primitives use standard encoding (no whitespace)
		return json.Marshal(v)
	}
}

// canonicalizeArray produces canonical JSON for an array
func canonicalizeArray(arr []interface{}) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')

	for i, v := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		valBytes, err := canonicalizeValue(v)
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}

	buf.WriteByte(']')
	return buf.Bytes(), nil
}

// Sign signs an envelope with an Ed25519 private key
func Sign(env *Envelope, privKey ed25519.PrivateKey) error {
	// Ensure sig fields are clear before canonicalizing
	env.Sig = ""
	env.SigAlg = ""

	canonical, err := CanonicalJSON(env)
	if err != nil {
		return fmt.Errorf("canonical json: %w", err)
	}

	sig := ed25519.Sign(privKey, canonical)
	env.Sig = base64.StdEncoding.EncodeToString(sig)
	env.SigAlg = SigAlgEd25519
	return nil
}

// Verify verifies an envelope signature with an Ed25519 public key
func Verify(env *Envelope, pubKey ed25519.PublicKey) error {
	if env.SigAlg != SigAlgEd25519 {
		return fmt.Errorf("unsupported signature algorithm: %s", env.SigAlg)
	}

	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Create copy without sig fields for verification
	envCopy := *env
	envCopy.Sig = ""
	envCopy.SigAlg = ""

	canonical, err := CanonicalJSON(&envCopy)
	if err != nil {
		return fmt.Errorf("canonical json: %w", err)
	}

	if !ed25519.Verify(pubKey, canonical, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// SignEnvelopeData signs raw envelope data (map) with an Ed25519 private key
func SignEnvelopeData(data map[string]interface{}, privKey ed25519.PrivateKey) (string, error) {
	// Remove sig fields for signing
	dataCopy := make(map[string]interface{}, len(data))
	for k, v := range data {
		if k != "sig" && k != "sigAlg" {
			dataCopy[k] = v
		}
	}

	canonical, err := canonicalizeMap(dataCopy)
	if err != nil {
		return "", fmt.Errorf("canonical json: %w", err)
	}

	sig := ed25519.Sign(privKey, canonical)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyEnvelopeData verifies raw envelope data (map) signature
func VerifyEnvelopeData(data map[string]interface{}, pubKey ed25519.PublicKey) error {
	sigAlg, ok := data["sigAlg"].(string)
	if !ok || sigAlg != SigAlgEd25519 {
		return fmt.Errorf("unsupported signature algorithm: %v", data["sigAlg"])
	}

	sigStr, ok := data["sig"].(string)
	if !ok {
		return errors.New("missing signature")
	}

	sig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Create copy without sig fields
	dataCopy := make(map[string]interface{}, len(data))
	for k, v := range data {
		if k != "sig" && k != "sigAlg" {
			dataCopy[k] = v
		}
	}

	canonical, err := canonicalizeMap(dataCopy)
	if err != nil {
		return fmt.Errorf("canonical json: %w", err)
	}

	if !ed25519.Verify(pubKey, canonical, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// seenEntry tracks when an event ID was seen
type seenEntry struct {
	id   string
	seen time.Time
}

// Deduplicator tracks seen event IDs for deduplication
type Deduplicator struct {
	mu      sync.RWMutex
	seen    map[string]time.Time
	entries []seenEntry // ordered by insertion time for pruning
}

// NewDeduplicator creates a new deduplicator
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen:    make(map[string]time.Time),
		entries: make([]seenEntry, 0, DedupeMaxEvents),
	}
}

// IsDuplicate checks if an event ID has been seen, and marks it as seen if not
// Returns true if duplicate, false if new
func (d *Deduplicator) IsDuplicate(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.seen[id]; ok {
		return true
	}

	now := time.Now()
	d.seen[id] = now
	d.entries = append(d.entries, seenEntry{id: id, seen: now})

	// Prune if needed (by count or age)
	d.prune(now)

	return false
}

// prune removes old entries (must be called with lock held)
func (d *Deduplicator) prune(now time.Time) {
	cutoff := now.Add(-DedupeMaxAge)

	// Prune by age first
	pruneIdx := 0
	for pruneIdx < len(d.entries) && d.entries[pruneIdx].seen.Before(cutoff) {
		delete(d.seen, d.entries[pruneIdx].id)
		pruneIdx++
	}

	// Prune by count if still too many
	for len(d.entries)-pruneIdx > DedupeMaxEvents {
		delete(d.seen, d.entries[pruneIdx].id)
		pruneIdx++
	}

	if pruneIdx > 0 {
		d.entries = d.entries[pruneIdx:]
	}
}

// Count returns the number of entries being tracked
func (d *Deduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.seen)
}

// NewEnvelope creates a new envelope with common fields
func NewEnvelope(msgType, serverURN string, clock *LamportClock) *Envelope {
	seq := clock.Next()
	return &Envelope{
		Context: S2SContextURL,
		Type:    msgType,
		ID:      fmt.Sprintf("urn:irc:event:%s:%d", extractHostname(serverURN), seq),
		Seq:     seq,
		Origin:  serverURN,
		Ts:      time.Now().UTC().Format(time.RFC3339),
		Payload: make(map[string]interface{}),
	}
}

// extractHostname extracts hostname from server URN
// e.g., "urn:irc:server:irc.example.com" -> "irc.example.com"
func extractHostname(urn string) string {
	const prefix = "urn:irc:server:"
	if len(urn) > len(prefix) {
		return urn[len(prefix):]
	}
	return urn
}

// MakeServerURN creates a server URN from hostname
func MakeServerURN(hostname string) string {
	return "urn:irc:server:" + hostname
}

// MakeUserURN creates a user URN from server hostname and nick
func MakeUserURN(serverHost, nick string) string {
	return fmt.Sprintf("urn:irc:user:%s:%s", serverHost, nick)
}

// MakeChannelURN creates a channel URN from channel name
// Channel names have # prefix stripped
func MakeChannelURN(name string) string {
	if len(name) > 0 && name[0] == '#' {
		name = name[1:]
	}
	return "urn:irc:channel:" + name
}

// MakeEventURN creates an event URN
func MakeEventURN(serverHost string, seq int64) string {
	return fmt.Sprintf("urn:irc:event:%s:%d", serverHost, seq)
}

// GenerateNonce generates a random nonce for ping/pong
func GenerateNonce() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}
