package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Discovery constants
const (
	DiscoveryPollInterval = 5 * time.Minute
	DiscoveryCacheMaxAge  = 24 * time.Hour
	HTTPTimeout           = 30 * time.Second
	DefaultS2SPort        = 6697
)

// ServerConfig represents a server entry in servers.json
type ServerConfig struct {
	Port        int    `json:"port"`
	Pubkey      string `json:"pubkey"`
	Admin       string `json:"admin,omitempty"`
	Location    string `json:"location,omitempty"`
	Description string `json:"description,omitempty"`
}

// ParsedPubkey returns the decoded Ed25519 public key
func (sc *ServerConfig) ParsedPubkey() (ed25519.PublicKey, error) {
	return ParsePubkey(sc.Pubkey)
}

// ParsePubkey parses an "ed25519:<base64>" formatted public key
func ParsePubkey(s string) (ed25519.PublicKey, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(s, prefix) {
		return nil, errors.New("pubkey must start with 'ed25519:'")
	}

	data, err := base64.StdEncoding.DecodeString(s[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("decode pubkey: %w", err)
	}

	// Ed25519 public keys are 32 bytes, but might be DER-encoded
	// Try raw key first
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(data), nil
	}

	// Handle DER-encoded SPKI format (44 bytes for Ed25519)
	// The last 32 bytes of the DER encoding are the raw key
	if len(data) >= 44 {
		// DER structure: SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { key } }
		// For Ed25519, raw key starts at offset 12
		return ed25519.PublicKey(data[len(data)-ed25519.PublicKeySize:]), nil
	}

	return nil, fmt.Errorf("invalid pubkey length: %d", len(data))
}

// EncodePubkey encodes an Ed25519 public key to "ed25519:<base64>" format
func EncodePubkey(key ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(key)
}

// NetworkConfig represents servers.json content
type NetworkConfig struct {
	Network string                   `json:"network"`
	Version int                      `json:"version,omitempty"`
	Servers map[string]*ServerConfig `json:"servers"`
}

// Validate checks the network config for errors
func (nc *NetworkConfig) Validate() error {
	if nc.Network == "" {
		return errors.New("network name is required")
	}
	if nc.Servers == nil || len(nc.Servers) == 0 {
		return errors.New("at least one server is required")
	}

	for hostname, server := range nc.Servers {
		if err := nc.validateServer(hostname, server); err != nil {
			return err
		}
	}
	return nil
}

func (nc *NetworkConfig) validateServer(hostname string, server *ServerConfig) error {
	if hostname == "" {
		return errors.New("server hostname cannot be empty")
	}
	if server.Port < 1 || server.Port > 65535 {
		return fmt.Errorf("server %s: invalid port %d", hostname, server.Port)
	}
	if server.Pubkey == "" {
		return fmt.Errorf("server %s: pubkey is required", hostname)
	}
	if _, err := server.ParsedPubkey(); err != nil {
		return fmt.Errorf("server %s: %w", hostname, err)
	}
	return nil
}

// CachedConfig holds servers.json with caching metadata
type CachedConfig struct {
	Config    *NetworkConfig
	ETag      string
	FetchedAt time.Time
}

// Discovery manages peer discovery via GitHub-hosted servers.json
type Discovery struct {
	url       string
	cachePath string
	token     string // GitHub API token for private repos

	mu     sync.RWMutex
	config *CachedConfig
	motd   []string // cached network MOTD lines
	client *http.Client
}

// NewDiscovery creates a new Discovery instance
func NewDiscovery(url, cachePath, token string) *Discovery {
	return &Discovery{
		url:       url,
		cachePath: cachePath,
		token:     token,
		client: &http.Client{
			Timeout: HTTPTimeout,
		},
	}
}

// LoadCached loads the cached config from disk
func (d *Discovery) LoadCached() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	data, err := os.ReadFile(d.cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no cache yet
		}
		return fmt.Errorf("read cache: %w", err)
	}

	var config NetworkConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse cached config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return fmt.Errorf("cached config invalid: %w", err)
	}

	// Load ETag if present
	etag := ""
	etagPath := d.cachePath + ".etag"
	if data, err := os.ReadFile(etagPath); err == nil {
		etag = strings.TrimSpace(string(data))
	}

	// Load fetch time if present
	fetchedAt := time.Time{}
	fetchedPath := d.cachePath + ".fetched"
	if data, err := os.ReadFile(fetchedPath); err == nil {
		fetchedAt, _ = time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	}

	d.config = &CachedConfig{
		Config:    &config,
		ETag:      etag,
		FetchedAt: fetchedAt,
	}

	return nil
}

// Fetch fetches servers.json from the configured URL
// Returns true if config changed, false if unchanged (304)
func (d *Discovery) Fetch() (bool, error) {
	d.mu.RLock()
	currentETag := ""
	if d.config != nil {
		currentETag = d.config.ETag
	}
	d.mu.RUnlock()

	req, err := http.NewRequest("GET", d.url, nil)
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}

	// Set conditional fetch header
	if currentETag != "" {
		req.Header.Set("If-None-Match", currentETag)
	}

	// Set auth for private repos
	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ircd-federation/1.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// Config unchanged, update fetch time
		d.mu.Lock()
		if d.config != nil {
			d.config.FetchedAt = time.Now()
		}
		d.mu.Unlock()
		return false, nil

	case http.StatusOK:
		// Parse new config
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("read body: %w", err)
		}

		var config NetworkConfig
		if err := json.Unmarshal(body, &config); err != nil {
			return false, fmt.Errorf("parse config: %w", err)
		}

		if err := config.Validate(); err != nil {
			return false, fmt.Errorf("invalid config: %w", err)
		}

		// Update cache
		d.mu.Lock()
		d.config = &CachedConfig{
			Config:    &config,
			ETag:      resp.Header.Get("ETag"),
			FetchedAt: time.Now(),
		}
		d.mu.Unlock()

		// Write cache to disk
		if err := d.saveCache(body, resp.Header.Get("ETag")); err != nil {
			// Log but don't fail - we have the config in memory
			fmt.Printf("warning: failed to save cache: %v\n", err)
		}

		return true, nil

	default:
		return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

// saveCache writes the config to disk
func (d *Discovery) saveCache(data []byte, etag string) error {
	dir := filepath.Dir(d.cachePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	if err := os.WriteFile(d.cachePath, data, 0600); err != nil {
		return err
	}

	if etag != "" {
		if err := os.WriteFile(d.cachePath+".etag", []byte(etag), 0600); err != nil {
			return err
		}
	}

	fetchTime := time.Now().Format(time.RFC3339)
	return os.WriteFile(d.cachePath+".fetched", []byte(fetchTime), 0600)
}

// FetchMOTD fetches motd.txt from the same base URL as servers.json
func (d *Discovery) FetchMOTD() error {
	// Derive motd.txt URL from servers.json URL
	motdURL := strings.TrimSuffix(d.url, "servers.json") + "motd.txt"

	req, err := http.NewRequest("GET", motdURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	req.Header.Set("User-Agent", "meshircd/1.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch motd: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// No network MOTD, that's fine
		d.mu.Lock()
		d.motd = nil
		d.mu.Unlock()
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read motd: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	d.mu.Lock()
	d.motd = lines
	d.mu.Unlock()

	return nil
}

// GetMOTD returns the cached network MOTD lines
func (d *Discovery) GetMOTD() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.motd
}

// GetConfig returns the current config
func (d *Discovery) GetConfig() *NetworkConfig {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.config != nil {
		return d.config.Config
	}
	return nil
}

// GetServer returns config for a specific server hostname
func (d *Discovery) GetServer(hostname string) *ServerConfig {
	config := d.GetConfig()
	if config == nil {
		return nil
	}
	return config.Servers[hostname]
}

// GetPeers returns all server hostnames except the specified one (self)
func (d *Discovery) GetPeers(selfHostname string) []string {
	config := d.GetConfig()
	if config == nil {
		return nil
	}

	peers := make([]string, 0, len(config.Servers))
	for hostname := range config.Servers {
		if hostname != selfHostname {
			peers = append(peers, hostname)
		}
	}
	return peers
}

// IsCacheStale returns true if the cache is older than maxAge
func (d *Discovery) IsCacheStale(maxAge time.Duration) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.config == nil {
		return true
	}
	return time.Since(d.config.FetchedAt) > maxAge
}

// Peer represents a connection to another server
type Peer struct {
	Hostname  string
	Port      int
	Pubkey    ed25519.PublicKey
	Conn      net.Conn
	Connected bool
	LastPing  time.Time
	LastPong  time.Time
	Vector    map[string]int64 // their last reported vector
	Caps      []string         // their capabilities

	mu sync.RWMutex
}

// NewPeer creates a Peer from server config
func NewPeer(hostname string, config *ServerConfig) (*Peer, error) {
	pubkey, err := config.ParsedPubkey()
	if err != nil {
		return nil, err
	}

	return &Peer{
		Hostname: hostname,
		Port:     config.Port,
		Pubkey:   pubkey,
		Vector:   make(map[string]int64),
	}, nil
}

// Connect establishes TLS connection and verifies pubkey
func (p *Peer) Connect(ownPrivKey ed25519.PrivateKey) error {
	addr := fmt.Sprintf("%s:%d", p.Hostname, p.Port)

	// Configure TLS
	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // We verify pubkey manually
	}

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	// Verify peer certificate against expected pubkey
	if err := p.verifyPeerCert(conn); err != nil {
		conn.Close()
		return err
	}

	p.mu.Lock()
	p.Conn = conn
	p.Connected = true
	p.mu.Unlock()

	return nil
}

// verifyPeerCert verifies the peer's TLS certificate matches expected pubkey
func (p *Peer) verifyPeerCert(conn *tls.Conn) error {
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
func (p *Peer) Disconnect() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Conn != nil {
		p.Conn.Close()
		p.Conn = nil
	}
	p.Connected = false
}

// IsConnected returns whether the peer is connected
func (p *Peer) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Connected
}

// UpdateVector updates the peer's reported vector
func (p *Peer) UpdateVector(v map[string]int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Vector = v
}

// PeerManager manages connections to all peers
type PeerManager struct {
	discovery   *Discovery
	selfHost    string
	privKey     ed25519.PrivateKey

	mu    sync.RWMutex
	peers map[string]*Peer
}

// NewPeerManager creates a new PeerManager
func NewPeerManager(discovery *Discovery, selfHost string, privKey ed25519.PrivateKey) *PeerManager {
	return &PeerManager{
		discovery: discovery,
		selfHost:  selfHost,
		privKey:   privKey,
		peers:     make(map[string]*Peer),
	}
}

// SyncPeers updates peer list based on current discovery config
// Connects to new peers, disconnects from removed peers
func (pm *PeerManager) SyncPeers() error {
	config := pm.discovery.GetConfig()
	if config == nil {
		return errors.New("no config available")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Track which peers should exist
	current := make(map[string]bool)
	for hostname := range config.Servers {
		if hostname != pm.selfHost {
			current[hostname] = true
		}
	}

	// Disconnect removed peers
	for hostname, peer := range pm.peers {
		if !current[hostname] {
			peer.Disconnect()
			delete(pm.peers, hostname)
		}
	}

	// Connect to new peers
	for hostname := range current {
		if _, exists := pm.peers[hostname]; !exists {
			serverConfig := config.Servers[hostname]
			peer, err := NewPeer(hostname, serverConfig)
			if err != nil {
				fmt.Printf("warning: failed to create peer %s: %v\n", hostname, err)
				continue
			}

			pm.peers[hostname] = peer

			// Connect in goroutine to not block
			go func(p *Peer) {
				if err := p.Connect(pm.privKey); err != nil {
					fmt.Printf("warning: failed to connect to %s: %v\n", p.Hostname, err)
				}
			}(peer)
		}
	}

	return nil
}

// GetPeer returns a peer by hostname
func (pm *PeerManager) GetPeer(hostname string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.peers[hostname]
}

// GetConnectedPeers returns all connected peers
func (pm *PeerManager) GetConnectedPeers() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var connected []*Peer
	for _, peer := range pm.peers {
		if peer.IsConnected() {
			connected = append(connected, peer)
		}
	}
	return connected
}

// Broadcast sends a message to all connected peers
func (pm *PeerManager) Broadcast(data []byte) {
	for _, peer := range pm.GetConnectedPeers() {
		if peer.Conn != nil {
			// Append newline for NDJSON framing
			_, _ = peer.Conn.Write(append(data, '\n'))
		}
	}
}

// LoadNetworkConfig loads and validates a servers.json file
func LoadNetworkConfig(path string) (*NetworkConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var config NetworkConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}
