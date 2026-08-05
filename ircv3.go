package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// IRCv3 SASL numerics
const (
	RPL_LOGGEDIN    = "900"
	RPL_LOGGEDOUT   = "901"
	ERR_NICKLOCKED  = "902"
	RPL_SASLSUCCESS = "903"
	ERR_SASLFAIL    = "904"
	ERR_SASLTOOLONG = "905"
	ERR_SASLABORTED = "906"
	ERR_SASLALREADY = "907"
	RPL_SASLMECHS   = "908"
)

// SASL states
type SASLState int

const (
	SASLNone SASLState = iota
	SASLInitiated
	SASLWaitingResponse
	SASLCompleted
)

// SASLSession tracks SASL authentication state for a client
type SASLSession struct {
	State     SASLState
	Mechanism string
	Buffer    []byte // accumulated AUTHENTICATE data
}

// Account represents an authenticated user account
type Account struct {
	Name     string // nick/account name
	DID      string // did:key or did:web
	Password string // hashed password for PLAIN (optional)
}

// AccountStore manages user accounts
type AccountStore struct {
	mu       sync.RWMutex
	accounts map[string]*Account  // lowercase account name -> account
	byDID    map[string]*Account  // did -> account
}

func newAccountStore() *AccountStore {
	return &AccountStore{
		accounts: make(map[string]*Account),
		byDID:    make(map[string]*Account),
	}
}

func (s *AccountStore) Register(account *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(account.Name)
	s.accounts[key] = account
	if account.DID != "" {
		s.byDID[account.DID] = account
	}
}

func (s *AccountStore) GetByName(name string) *Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accounts[strings.ToLower(name)]
}

func (s *AccountStore) GetByDID(did string) *Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byDID[did]
}

// MessageIDGenerator generates unique message IDs in server/seq format
type MessageIDGenerator struct {
	serverName string
	seq        uint64
}

func newMessageIDGenerator(serverName string) *MessageIDGenerator {
	return &MessageIDGenerator{serverName: serverName}
}

func (g *MessageIDGenerator) Next() string {
	seq := atomic.AddUint64(&g.seq, 1)
	return fmt.Sprintf("%s/%d", g.serverName, seq)
}

// LabeledResponse tracks client labels for response correlation
type LabeledResponseTracker struct {
	mu     sync.RWMutex
	labels map[*Client]string // current label per client
}

func newLabeledResponseTracker() *LabeledResponseTracker {
	return &LabeledResponseTracker{
		labels: make(map[*Client]string),
	}
}

func (t *LabeledResponseTracker) SetLabel(c *Client, label string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if label == "" {
		delete(t.labels, c)
	} else {
		t.labels[c] = label
	}
}

func (t *LabeledResponseTracker) GetLabel(c *Client) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.labels[c]
}

func (t *LabeledResponseTracker) ClearLabel(c *Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.labels, c)
}

// ParsedIRCMessage extends Message with IRCv3 message tags
type ParsedIRCMessage struct {
	*Message
	Tags map[string]string
}

// ParseMessageWithTags parses an IRC message including IRCv3 tags
func ParseMessageWithTags(line string) *ParsedIRCMessage {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil
	}

	tags := make(map[string]string)

	// Parse tags (starts with @)
	if line[0] == '@' {
		idx := strings.Index(line, " ")
		if idx == -1 {
			return nil
		}
		tagStr := line[1:idx]
		line = line[idx+1:]

		for _, tag := range strings.Split(tagStr, ";") {
			if eqIdx := strings.Index(tag, "="); eqIdx != -1 {
				key := tag[:eqIdx]
				value := unescapeTagValue(tag[eqIdx+1:])
				tags[key] = value
			} else {
				tags[tag] = ""
			}
		}
	}

	msg := parseMessage(line)
	if msg == nil {
		return nil
	}

	return &ParsedIRCMessage{
		Message: msg,
		Tags:    tags,
	}
}

// unescapeTagValue unescapes IRCv3 tag values
func unescapeTagValue(s string) string {
	s = strings.ReplaceAll(s, "\\:", ";")
	s = strings.ReplaceAll(s, "\\s", " ")
	s = strings.ReplaceAll(s, "\\r", "\r")
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}

// escapeTagValue escapes a value for IRCv3 message tags
func escapeTagValue(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, ";", "\\:")
	s = strings.ReplaceAll(s, " ", "\\s")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// FormatTags formats tags for an IRC message
func FormatTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}

	var parts []string
	for k, v := range tags {
		if v == "" {
			parts = append(parts, k)
		} else {
			parts = append(parts, k+"="+escapeTagValue(v))
		}
	}
	return "@" + strings.Join(parts, ";") + " "
}

// ServerTime returns the current time in IRCv3 server-time format
func ServerTime() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// ExtractDIDFromTLSCert extracts a did:key from a TLS client certificate
// The cert must contain an Ed25519 public key
func ExtractDIDFromTLSCert(tlsState *tls.ConnectionState) (string, error) {
	if tlsState == nil {
		return "", fmt.Errorf("no TLS connection state")
	}

	if len(tlsState.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate presented")
	}

	cert := tlsState.PeerCertificates[0]

	// Extract public key from certificate
	switch pubKey := cert.PublicKey.(type) {
	case ed25519.PublicKey:
		return CreateDIDKey(pubKey), nil
	default:
		// Try to extract raw public key for other key types
		// This handles certificates where the key is stored differently
		if pkBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey); err == nil {
			// Check if it's an Ed25519 key wrapped in PKIX format
			parsed, err := x509.ParsePKIXPublicKey(pkBytes)
			if err == nil {
				if edKey, ok := parsed.(ed25519.PublicKey); ok {
					return CreateDIDKey(edKey), nil
				}
			}
		}
		return "", fmt.Errorf("certificate does not contain Ed25519 key")
	}
}

// SASL PLAIN authentication
// Format: base64(authzid \0 authcid \0 password)
func ParseSASLPlain(data []byte) (authzid, authcid, password string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return "", "", "", fmt.Errorf("invalid base64: %w", err)
	}

	parts := strings.SplitN(string(decoded), "\x00", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid PLAIN format: expected 3 parts, got %d", len(parts))
	}

	authzid = parts[0]
	authcid = parts[1]
	password = parts[2]

	// If authzid is empty, use authcid
	if authzid == "" {
		authzid = authcid
	}

	return authzid, authcid, password, nil
}

// IRCv3Handler handles IRCv3-specific protocol extensions
type IRCv3Handler struct {
	server       *Server
	msgIDGen     *MessageIDGenerator
	accounts     *AccountStore
	labelTracker *LabeledResponseTracker
}

func newIRCv3Handler(server *Server) *IRCv3Handler {
	return &IRCv3Handler{
		server:       server,
		msgIDGen:     newMessageIDGenerator(server.name),
		accounts:     newAccountStore(),
		labelTracker: newLabeledResponseTracker(),
	}
}

// HandleAUTHENTICATE processes SASL AUTHENTICATE commands
func (h *IRCv3Handler) HandleAUTHENTICATE(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "AUTHENTICATE :Not enough parameters")
		return
	}

	// Check if already authenticated
	if c.account != "" {
		c.SendNumeric(ERR_SASLALREADY, ":You have already authenticated")
		return
	}

	// Check if SASL capability was requested
	if !c.caps["sasl"] {
		c.SendNumeric(ERR_SASLFAIL, ":SASL authentication failed (capability not enabled)")
		return
	}

	param := msg.Params[0]

	switch c.sasl.State {
	case SASLNone:
		// Initial mechanism selection
		mechanism := strings.ToUpper(param)
		switch mechanism {
		case "EXTERNAL":
			c.sasl.State = SASLWaitingResponse
			c.sasl.Mechanism = mechanism
			c.Send(fmt.Sprintf(":%s AUTHENTICATE +", h.server.name))
		case "PLAIN":
			c.sasl.State = SASLWaitingResponse
			c.sasl.Mechanism = mechanism
			c.Send(fmt.Sprintf(":%s AUTHENTICATE +", h.server.name))
		case "*":
			// Abort SASL
			c.sasl = SASLSession{}
			c.SendNumeric(ERR_SASLABORTED, ":SASL authentication aborted")
		default:
			c.SendNumeric(ERR_SASLFAIL, fmt.Sprintf(":SASL mechanism %s not supported", mechanism))
			c.SendNumeric(RPL_SASLMECHS, "EXTERNAL,PLAIN :are available SASL mechanisms")
		}

	case SASLWaitingResponse:
		if param == "*" {
			// Abort
			c.sasl = SASLSession{}
			c.SendNumeric(ERR_SASLABORTED, ":SASL authentication aborted")
			return
		}

		if param == "+" {
			// Empty response, valid for EXTERNAL
			h.finishSASL(c, nil)
			return
		}

		// Accumulate data (for multi-line responses)
		if len(param) == 400 {
			// More data coming
			c.sasl.Buffer = append(c.sasl.Buffer, []byte(param)...)
			if len(c.sasl.Buffer) > 8192 {
				c.sasl = SASLSession{}
				c.SendNumeric(ERR_SASLTOOLONG, ":SASL message too long")
			}
			return
		}

		// Final chunk
		data := append(c.sasl.Buffer, []byte(param)...)
		h.finishSASL(c, data)

	case SASLCompleted:
		c.SendNumeric(ERR_SASLALREADY, ":You have already authenticated")
	}
}

// finishSASL completes SASL authentication
func (h *IRCv3Handler) finishSASL(c *Client, data []byte) {
	defer func() {
		c.sasl = SASLSession{}
	}()

	switch c.sasl.Mechanism {
	case "EXTERNAL":
		h.authExternal(c)
	case "PLAIN":
		h.authPlain(c, data)
	default:
		c.SendNumeric(ERR_SASLFAIL, ":SASL authentication failed")
	}
}

// authExternal authenticates via TLS client certificate
func (h *IRCv3Handler) authExternal(c *Client) {
	tlsConn, ok := c.conn.(*tls.Conn)
	if !ok {
		c.SendNumeric(ERR_SASLFAIL, ":SASL EXTERNAL requires TLS")
		return
	}

	tlsState := tlsConn.ConnectionState()
	did, err := ExtractDIDFromTLSCert(&tlsState)
	if err != nil {
		c.SendNumeric(ERR_SASLFAIL, fmt.Sprintf(":SASL EXTERNAL failed: %s", err.Error()))
		return
	}

	// Look up account by DID
	account := h.accounts.GetByDID(did)
	if account == nil {
		// Auto-register: create account with this DID
		account = &Account{
			Name: c.Nick(),
			DID:  did,
		}
		h.accounts.Register(account)
	}

	h.completeAuth(c, account)
}

// authPlain authenticates via username/password
func (h *IRCv3Handler) authPlain(c *Client, data []byte) {
	_, authcid, password, err := ParseSASLPlain(data)
	if err != nil {
		c.SendNumeric(ERR_SASLFAIL, ":SASL PLAIN: invalid format")
		return
	}

	account := h.accounts.GetByName(authcid)
	if account == nil || account.Password == "" {
		c.SendNumeric(ERR_SASLFAIL, ":SASL authentication failed")
		return
	}

	// ponytail: simple password check, production would use argon2/bcrypt
	if account.Password != password {
		c.SendNumeric(ERR_SASLFAIL, ":SASL authentication failed")
		return
	}

	h.completeAuth(c, account)
}

// completeAuth finishes successful authentication
func (h *IRCv3Handler) completeAuth(c *Client, account *Account) {
	c.mu.Lock()
	c.account = account.Name
	c.did = account.DID
	c.sasl.State = SASLCompleted
	c.mu.Unlock()

	c.SendNumeric(RPL_LOGGEDIN, fmt.Sprintf("%s %s :You are now logged in as %s", c.Prefix(), account.Name, account.Name))
	c.SendNumeric(RPL_SASLSUCCESS, ":SASL authentication successful")
}

// BuildMessageTags builds IRCv3 tags for an outgoing message
func (h *IRCv3Handler) BuildMessageTags(sender *Client, label string) map[string]string {
	tags := make(map[string]string)

	// Always add msgid and time
	tags["msgid"] = h.msgIDGen.Next()
	tags["time"] = ServerTime()

	// Add label if present
	if label != "" {
		tags["label"] = label
	}

	// Add account tag if sender is logged in
	if sender != nil {
		sender.mu.RLock()
		account := sender.account
		did := sender.did
		sender.mu.RUnlock()

		if account != "" {
			tags["account"] = account
		}
		if did != "" {
			tags["did"] = did
		}
	}

	return tags
}

// SendWithTags sends a message with IRCv3 tags
func (h *IRCv3Handler) SendWithTags(c *Client, tags map[string]string, line string) {
	tagStr := FormatTags(tags)
	c.Send(tagStr + line)
}

// SendEchoMessage echoes a PRIVMSG/NOTICE back to the sender if they have echo-message cap
func (h *IRCv3Handler) SendEchoMessage(c *Client, target, text string, isNotice bool, label string) {
	if !c.caps["echo-message"] {
		return
	}

	cmd := "PRIVMSG"
	if isNotice {
		cmd = "NOTICE"
	}

	tags := h.BuildMessageTags(c, label)
	line := fmt.Sprintf(":%s %s %s :%s", c.Prefix(), cmd, target, text)
	h.SendWithTags(c, tags, line)
}

// BroadcastWithTags sends a message to all channel members with appropriate tags
func (h *IRCv3Handler) BroadcastWithTags(ch *Channel, sender *Client, line string, excludeSender bool) {
	// Build base tags (without label, labels are per-request)
	baseTags := h.BuildMessageTags(sender, "")

	for member := range ch.members {
		if excludeSender && member == sender {
			continue
		}

		// Filter tags based on member's capabilities
		memberTags := h.filterTagsForClient(member, baseTags)
		h.SendWithTags(member, memberTags, line)
	}
}

// filterTagsForClient filters tags based on client capabilities
func (h *IRCv3Handler) filterTagsForClient(c *Client, tags map[string]string) map[string]string {
	result := make(map[string]string)

	for k, v := range tags {
		switch k {
		case "msgid":
			if c.caps["message-ids"] {
				result[k] = v
			}
		case "time":
			if c.caps["server-time"] {
				result[k] = v
			}
		case "account":
			if c.caps["account-tag"] {
				result[k] = v
			}
		case "did":
			if c.caps["identity"] {
				result[k] = v
			}
		case "label":
			if c.caps["labeled-response"] {
				result[k] = v
			}
		default:
			// Pass through other tags if client supports message-tags
			if c.caps["message-tags"] {
				result[k] = v
			}
		}
	}

	return result
}

// HandleLabeledRequest extracts label from request and tracks it
func (h *IRCv3Handler) HandleLabeledRequest(c *Client, tags map[string]string) string {
	if !c.caps["labeled-response"] {
		return ""
	}
	label := tags["label"]
	h.labelTracker.SetLabel(c, label)
	return label
}

// SendACK sends an ACK for commands that produce no other response
func (h *IRCv3Handler) SendACK(c *Client, label string) {
	if label == "" {
		return
	}
	tags := map[string]string{"label": label}
	h.SendWithTags(c, tags, fmt.Sprintf(":%s ACK", h.server.name))
}
