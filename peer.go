package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// PeerState represents the connection state of a peer
type PeerState int

const (
	PeerStateDisconnected PeerState = iota
	PeerStateConnecting
	PeerStateHandshaking
	PeerStateConnected
	PeerStateSyncing
	PeerStateReady
)

func (s PeerState) String() string {
	switch s {
	case PeerStateDisconnected:
		return "disconnected"
	case PeerStateConnecting:
		return "connecting"
	case PeerStateHandshaking:
		return "handshaking"
	case PeerStateConnected:
		return "connected"
	case PeerStateSyncing:
		return "syncing"
	case PeerStateReady:
		return "ready"
	default:
		return "unknown"
	}
}

// PeerConnection represents a connection to another IRC server
type PeerConnection struct {
	Hostname string
	Port     int
	Pubkey   ed25519.PublicKey

	mu           sync.RWMutex
	state        PeerState
	conn         net.Conn
	reader       *bufio.Reader
	sendCh       chan []byte
	stopCh       chan struct{}
	vector       map[string]int64 // their last reported vector
	caps         []string         // their capabilities
	lastPing     time.Time
	lastPong     time.Time
	pendingPing  string // nonce of pending ping
	reconnectCnt int    // number of consecutive reconnect attempts

	onMessage func(*PeerConnection, *Envelope, map[string]interface{})
	onConnect func(*PeerConnection)
	onDisconnect func(*PeerConnection, error)
}

// NewPeerConnection creates a new peer connection
func NewPeerConnection(hostname string, port int, pubkey ed25519.PublicKey) *PeerConnection {
	return &PeerConnection{
		Hostname: hostname,
		Port:     port,
		Pubkey:   pubkey,
		state:    PeerStateDisconnected,
		vector:   make(map[string]int64),
		sendCh:   make(chan []byte, 256),
		stopCh:   make(chan struct{}),
	}
}

// State returns the current connection state
func (p *PeerConnection) State() PeerState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// SetState updates the connection state
func (p *PeerConnection) setState(state PeerState) {
	p.mu.Lock()
	p.state = state
	p.mu.Unlock()
}

// IsConnected returns true if the peer is connected and ready
func (p *PeerConnection) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state >= PeerStateConnected
}

// GetVector returns a copy of the peer's reported vector clock
func (p *PeerConnection) GetVector() map[string]int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	v := make(map[string]int64, len(p.vector))
	for k, val := range p.vector {
		v[k] = val
	}
	return v
}

// UpdateVector updates the peer's reported vector clock
func (p *PeerConnection) UpdateVector(v map[string]int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.vector = v
}

// SetCaps updates the peer's capabilities
func (p *PeerConnection) SetCaps(caps []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.caps = caps
}

// HasCap returns true if the peer has the specified capability
func (p *PeerConnection) HasCap(cap string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, c := range p.caps {
		if c == cap {
			return true
		}
	}
	return false
}

// Connect establishes TLS connection and starts read/write loops
func (p *PeerConnection) Connect(ownCert tls.Certificate) error {
	p.mu.Lock()
	if p.state != PeerStateDisconnected {
		p.mu.Unlock()
		return errors.New("peer already connecting or connected")
	}
	p.state = PeerStateConnecting
	p.stopCh = make(chan struct{})
	p.sendCh = make(chan []byte, 256)
	p.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", p.Hostname, p.Port)

	// Configure TLS
	config := &tls.Config{
		Certificates:       []tls.Certificate{ownCert},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // We verify pubkey manually
	}

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		p.setState(PeerStateDisconnected)
		return fmt.Errorf("dial: %w", err)
	}

	// Verify peer certificate against expected pubkey
	if err := p.verifyPeerCert(conn); err != nil {
		conn.Close()
		p.setState(PeerStateDisconnected)
		return err
	}

	p.mu.Lock()
	p.conn = conn
	p.reader = bufio.NewReader(conn)
	p.state = PeerStateHandshaking
	p.reconnectCnt = 0
	p.mu.Unlock()

	// Start read/write loops
	go p.writeLoop()
	go p.readLoop()
	go p.keepaliveLoop()

	// Notify connection established
	if p.onConnect != nil {
		p.onConnect(p)
	}

	return nil
}

// verifyPeerCert verifies the peer's TLS certificate matches expected pubkey
func (p *PeerConnection) verifyPeerCert(conn *tls.Conn) error {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("no peer certificate")
	}

	cert := state.PeerCertificates[0]
	peerPubkey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("peer certificate is not Ed25519")
	}

	if len(peerPubkey) != len(p.Pubkey) {
		return errors.New("pubkey length mismatch")
	}

	// Constant-time comparison
	match := true
	for i := range peerPubkey {
		if peerPubkey[i] != p.Pubkey[i] {
			match = false
		}
	}
	if !match {
		return errors.New("pubkey mismatch")
	}

	return nil
}

// Disconnect closes the peer connection
func (p *PeerConnection) Disconnect() {
	p.mu.Lock()
	if p.state == PeerStateDisconnected {
		p.mu.Unlock()
		return
	}

	// Signal loops to stop
	select {
	case <-p.stopCh:
		// Already closed
	default:
		close(p.stopCh)
	}

	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	p.state = PeerStateDisconnected
	p.mu.Unlock()

	// Notify disconnection
	if p.onDisconnect != nil {
		p.onDisconnect(p, nil)
	}
}

// Send queues a message to be sent to the peer
func (p *PeerConnection) Send(data []byte) error {
	p.mu.RLock()
	state := p.state
	p.mu.RUnlock()

	if state < PeerStateHandshaking {
		return errors.New("peer not connected")
	}

	select {
	case p.sendCh <- data:
		return nil
	default:
		return errors.New("send buffer full")
	}
}

// SendEnvelope marshals and sends an envelope
func (p *PeerConnection) SendEnvelope(env *Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	return p.Send(data)
}

// writeLoop handles writing messages to the peer
func (p *PeerConnection) writeLoop() {
	defer p.handleDisconnect(errors.New("write loop ended"))

	for {
		select {
		case <-p.stopCh:
			return
		case data := <-p.sendCh:
			p.mu.RLock()
			conn := p.conn
			p.mu.RUnlock()

			if conn == nil {
				return
			}

			// Set write deadline
			_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

			// Write message with newline (NDJSON framing)
			_, err := conn.Write(append(data, '\n'))
			if err != nil {
				return
			}
		}
	}
}

// readLoop handles reading messages from the peer
func (p *PeerConnection) readLoop() {
	defer p.handleDisconnect(errors.New("read loop ended"))

	for {
		select {
		case <-p.stopCh:
			return
		default:
		}

		p.mu.RLock()
		reader := p.reader
		conn := p.conn
		p.mu.RUnlock()

		if reader == nil || conn == nil {
			return
		}

		// Set read deadline
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// Read line (NDJSON framing)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				p.handleDisconnect(err)
			}
			return
		}

		// Parse envelope
		var raw map[string]interface{}
		if err := json.Unmarshal(line, &raw); err != nil {
			// Log and skip malformed messages
			continue
		}

		var env Envelope
		if err := json.Unmarshal(line, &env); err != nil {
			continue
		}

		// Handle message
		if p.onMessage != nil {
			p.onMessage(p, &env, raw)
		}
	}
}

// keepaliveLoop sends periodic pings and checks for pong timeouts
func (p *PeerConnection) keepaliveLoop() {
	ticker := time.NewTicker(PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			state := p.state

			// Check if we have a pending ping that hasn't been answered
			if p.pendingPing != "" {
				if time.Since(p.lastPing) > PongTimeout {
					p.mu.Unlock()
					p.handleDisconnect(errors.New("ping timeout"))
					return
				}
			}
			p.mu.Unlock()

			// Only send pings when connected and ready
			if state >= PeerStateConnected {
				p.sendPing()
			}
		}
	}
}

// sendPing sends a ping message
func (p *PeerConnection) sendPing() {
	nonce := GenerateNonce()

	p.mu.Lock()
	p.lastPing = time.Now()
	p.pendingPing = nonce
	p.mu.Unlock()

	// Create ping envelope - note: this requires access to server URN and clock
	// In practice, this would be called via the federation manager
	// For now, mark that a ping is expected
}

// HandlePong processes a pong response
func (p *PeerConnection) HandlePong(nonce string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.pendingPing == nonce {
		p.lastPong = time.Now()
		p.pendingPing = ""
	}
}

// handleDisconnect handles unexpected disconnection
func (p *PeerConnection) handleDisconnect(err error) {
	p.mu.Lock()
	if p.state == PeerStateDisconnected {
		p.mu.Unlock()
		return
	}

	// Signal loops to stop
	select {
	case <-p.stopCh:
		// Already closed
	default:
		close(p.stopCh)
	}

	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	p.state = PeerStateDisconnected
	p.mu.Unlock()

	// Notify disconnection
	if p.onDisconnect != nil {
		p.onDisconnect(p, err)
	}
}

// ReconnectWithBackoff attempts to reconnect with exponential backoff
func (p *PeerConnection) ReconnectWithBackoff(ownCert tls.Certificate) {
	p.mu.Lock()
	p.reconnectCnt++
	cnt := p.reconnectCnt
	p.mu.Unlock()

	// Calculate backoff: 5s, 10s, 20s, 40s, ... up to 5 minutes
	backoff := ReconnectInitial * time.Duration(1<<uint(cnt-1))
	if backoff > ReconnectMax {
		backoff = ReconnectMax
	}

	time.Sleep(backoff)

	// Check if we should still reconnect
	p.mu.RLock()
	state := p.state
	p.mu.RUnlock()

	if state != PeerStateDisconnected {
		return
	}

	if err := p.Connect(ownCert); err != nil {
		// Schedule another reconnect attempt
		go p.ReconnectWithBackoff(ownCert)
	}
}

// PeerRegistry manages all peer connections
type PeerRegistry struct {
	mu    sync.RWMutex
	peers map[string]*PeerConnection // hostname -> peer
}

// NewPeerRegistry creates a new peer registry
func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{
		peers: make(map[string]*PeerConnection),
	}
}

// Add adds a peer to the registry
func (r *PeerRegistry) Add(peer *PeerConnection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers[peer.Hostname] = peer
}

// Remove removes a peer from the registry
func (r *PeerRegistry) Remove(hostname string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if peer, ok := r.peers[hostname]; ok {
		peer.Disconnect()
		delete(r.peers, hostname)
	}
}

// Get returns a peer by hostname
func (r *PeerRegistry) Get(hostname string) *PeerConnection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.peers[hostname]
}

// GetAll returns all peers
func (r *PeerRegistry) GetAll() []*PeerConnection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	peers := make([]*PeerConnection, 0, len(r.peers))
	for _, p := range r.peers {
		peers = append(peers, p)
	}
	return peers
}

// GetConnected returns all connected peers
func (r *PeerRegistry) GetConnected() []*PeerConnection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var connected []*PeerConnection
	for _, p := range r.peers {
		if p.IsConnected() {
			connected = append(connected, p)
		}
	}
	return connected
}

// GetReady returns all peers in ready state
func (r *PeerRegistry) GetReady() []*PeerConnection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ready []*PeerConnection
	for _, p := range r.peers {
		if p.State() == PeerStateReady {
			ready = append(ready, p)
		}
	}
	return ready
}

// Broadcast sends data to all connected peers
func (r *PeerRegistry) Broadcast(data []byte) {
	for _, p := range r.GetConnected() {
		_ = p.Send(data)
	}
}

// BroadcastExcept sends data to all connected peers except one
func (r *PeerRegistry) BroadcastExcept(data []byte, exclude string) {
	for _, p := range r.GetConnected() {
		if p.Hostname != exclude {
			_ = p.Send(data)
		}
	}
}

// Close disconnects all peers
func (r *PeerRegistry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.peers {
		p.Disconnect()
	}
	r.peers = make(map[string]*PeerConnection)
}
