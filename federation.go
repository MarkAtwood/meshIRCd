package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// RemoteUser represents a user on another server
type RemoteUser struct {
	URN      string // urn:irc:user:server:nick
	Nick     string
	Ident    string
	Host     string
	Realname string
	Server   string // hostname of the server they're on
	Seq      int64  // sequence number from their UserOnline event
	Origin   string // origin server URN of their UserOnline event
	Identity string // JSON-LD identity document (if set)
	DID      string // DID extracted from identity
}

// Prefix returns the IRC-style prefix for the remote user
func (ru *RemoteUser) Prefix() string {
	return fmt.Sprintf("%s!%s@%s", ru.Nick, ru.Ident, ru.Host)
}

// FederationManager handles all S2S federation
type FederationManager struct {
	server     *Server
	hostname   string
	serverURN  string
	privKey    ed25519.PrivateKey
	tlsCert    tls.Certificate
	discovery  *Discovery
	peers      *PeerRegistry
	clock      *LamportClock
	dedupe     *Deduplicator
	eventStore *EventStore

	mu          sync.RWMutex
	remoteUsers map[string]*RemoteUser // user URN -> RemoteUser
	caps        []string               // our supported capabilities

	pollTicker *time.Ticker
	stopCh     chan struct{}
}

// EventStore stores events for delta sync
type EventStore struct {
	mu       sync.RWMutex
	events   []*StoredEvent
	byID     map[string]*StoredEvent
	byOrigin map[string][]*StoredEvent // origin -> events sorted by seq
	maxAge   time.Duration
	maxCount int
}

// StoredEvent is an event stored for replay during sync
type StoredEvent struct {
	ID     string
	Seq    int64
	Origin string
	Time   time.Time
	Data   []byte
}

// NewEventStore creates a new event store
func NewEventStore() *EventStore {
	return &EventStore{
		events:   make([]*StoredEvent, 0, 10000),
		byID:     make(map[string]*StoredEvent),
		byOrigin: make(map[string][]*StoredEvent),
		maxAge:   EventRetention,
		maxCount: 100000,
	}
}

// Store adds an event to the store
func (s *EventStore) Store(id string, seq int64, origin string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	event := &StoredEvent{
		ID:     id,
		Seq:    seq,
		Origin: origin,
		Time:   time.Now(),
		Data:   data,
	}

	s.events = append(s.events, event)
	s.byID[id] = event
	s.byOrigin[origin] = append(s.byOrigin[origin], event)

	// Prune old events
	s.prune()
}

// prune removes old events (must be called with lock held)
func (s *EventStore) prune() {
	cutoff := time.Now().Add(-s.maxAge)

	// Find prune index
	pruneIdx := 0
	for pruneIdx < len(s.events) && s.events[pruneIdx].Time.Before(cutoff) {
		pruneIdx++
	}

	// Also prune by count
	if len(s.events)-pruneIdx > s.maxCount {
		pruneIdx = len(s.events) - s.maxCount
	}

	if pruneIdx == 0 {
		return
	}

	// Remove pruned events from indexes
	for i := 0; i < pruneIdx; i++ {
		ev := s.events[i]
		delete(s.byID, ev.ID)
		// Note: byOrigin would need cleanup too in production
	}

	s.events = s.events[pruneIdx:]
}

// GetEventsSince returns events from an origin after the given sequence number
func (s *EventStore) GetEventsSince(origin string, afterSeq int64) [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events := s.byOrigin[origin]
	var result [][]byte
	for _, ev := range events {
		if ev.Seq > afterSeq {
			result = append(result, ev.Data)
		}
	}
	return result
}

// GetOldestSeq returns the oldest sequence number we have for an origin
func (s *EventStore) GetOldestSeq(origin string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events := s.byOrigin[origin]
	if len(events) == 0 {
		return 0
	}
	return events[0].Seq
}

// NewFederationManager creates a new federation manager
func NewFederationManager(server *Server, hostname string, privKey ed25519.PrivateKey, tlsCert tls.Certificate, discovery *Discovery) *FederationManager {
	return &FederationManager{
		server:      server,
		hostname:    hostname,
		serverURN:   MakeServerURN(hostname),
		privKey:     privKey,
		tlsCert:     tlsCert,
		discovery:   discovery,
		peers:       NewPeerRegistry(),
		clock:       NewLamportClock(),
		dedupe:      NewDeduplicator(),
		eventStore:  NewEventStore(),
		remoteUsers: make(map[string]*RemoteUser),
		caps:        []string{"delta-sync"},
		stopCh:      make(chan struct{}),
	}
}

// Start begins federation: connects to peers, starts polling
func (fm *FederationManager) Start() error {
	// Load cached discovery config
	if err := fm.discovery.LoadCached(); err != nil {
		log.Printf("federation: failed to load cached config: %v", err)
	}

	// Fetch fresh config
	if _, err := fm.discovery.Fetch(); err != nil {
		// If no cached config either, this is fatal
		if fm.discovery.GetConfig() == nil {
			return fmt.Errorf("federation: no config available: %w", err)
		}
		log.Printf("federation: failed to fetch config: %v (using cached)", err)
	}

	// Connect to peers
	fm.syncPeers()

	// Start polling for config updates
	fm.pollTicker = time.NewTicker(DiscoveryPollInterval)
	go fm.pollLoop()

	return nil
}

// Stop stops federation
func (fm *FederationManager) Stop() {
	close(fm.stopCh)
	if fm.pollTicker != nil {
		fm.pollTicker.Stop()
	}
	fm.peers.Close()
}

// pollLoop periodically fetches updated config
func (fm *FederationManager) pollLoop() {
	for {
		select {
		case <-fm.stopCh:
			return
		case <-fm.pollTicker.C:
			changed, err := fm.discovery.Fetch()
			if err != nil {
				log.Printf("federation: poll fetch failed: %v", err)
				continue
			}
			if changed {
				log.Printf("federation: config changed, syncing peers")
				fm.syncPeers()
			}
		}
	}
}

// syncPeers updates peer connections based on current config
func (fm *FederationManager) syncPeers() {
	config := fm.discovery.GetConfig()
	if config == nil {
		return
	}

	// Track which peers should exist
	shouldExist := make(map[string]bool)
	for hostname := range config.Servers {
		if hostname != fm.hostname {
			shouldExist[hostname] = true
		}
	}

	// Disconnect removed peers
	for _, peer := range fm.peers.GetAll() {
		if !shouldExist[peer.Hostname] {
			log.Printf("federation: removing peer %s", peer.Hostname)
			fm.peers.Remove(peer.Hostname)
		}
	}

	// Connect to new peers
	for hostname := range shouldExist {
		if fm.peers.Get(hostname) == nil {
			serverConfig := config.Servers[hostname]
			pubkey, err := serverConfig.ParsedPubkey()
			if err != nil {
				log.Printf("federation: failed to parse pubkey for %s: %v", hostname, err)
				continue
			}

			peer := NewPeerConnection(hostname, serverConfig.Port, pubkey)
			peer.onMessage = fm.handlePeerMessage
			peer.onConnect = fm.handlePeerConnect
			peer.onDisconnect = fm.handlePeerDisconnect

			fm.peers.Add(peer)

			// Connect in goroutine
			go func(p *PeerConnection) {
				if err := p.Connect(fm.tlsCert); err != nil {
					log.Printf("federation: failed to connect to %s: %v", p.Hostname, err)
					go p.ReconnectWithBackoff(fm.tlsCert)
				}
			}(peer)
		}
	}
}

// handlePeerConnect is called when a peer connects
func (fm *FederationManager) handlePeerConnect(peer *PeerConnection) {
	log.Printf("federation: connected to %s", peer.Hostname)
	peer.setState(PeerStateConnected)

	// Send Hello
	fm.sendHello(peer)
}

// handlePeerDisconnect is called when a peer disconnects
func (fm *FederationManager) handlePeerDisconnect(peer *PeerConnection, err error) {
	log.Printf("federation: disconnected from %s: %v", peer.Hostname, err)

	// Remove all remote users from this server
	fm.removeUsersFromServer(peer.Hostname)

	// Schedule reconnect
	go peer.ReconnectWithBackoff(fm.tlsCert)
}

// handlePeerMessage processes an incoming S2S message
func (fm *FederationManager) handlePeerMessage(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	// Verify signature
	serverConfig := fm.discovery.GetServer(peer.Hostname)
	if serverConfig == nil {
		log.Printf("federation: unknown origin %s", peer.Hostname)
		fm.sendError(peer, ErrUnknownOrigin, "unknown origin server", env.ID)
		return
	}

	pubkey, err := serverConfig.ParsedPubkey()
	if err != nil {
		log.Printf("federation: invalid pubkey for %s: %v", peer.Hostname, err)
		return
	}

	if err := VerifyEnvelopeData(raw, pubkey); err != nil {
		log.Printf("federation: signature verification failed for %s: %v", peer.Hostname, err)
		fm.sendError(peer, ErrInvalidSignature, "signature verification failed", env.ID)
		return
	}

	// Check for duplicate
	if fm.dedupe.IsDuplicate(env.ID) {
		return // Already processed
	}

	// Update Lamport clock
	fm.clock.Merge(env.Origin, env.Seq)

	// Store event for delta sync (except for transient events like Ping/Pong)
	switch env.Type {
	case TypePing, TypePong, TypeSyncRequest, TypeSyncResponse, TypeError:
		// Don't store transient messages
	default:
		data, _ := json.Marshal(raw)
		fm.eventStore.Store(env.ID, env.Seq, env.Origin, data)
	}

	// Handle by type
	switch env.Type {
	case TypeHello:
		fm.handleHello(peer, env, raw)
	case TypePing:
		fm.handlePing(peer, env, raw)
	case TypePong:
		fm.handlePong(peer, env, raw)
	case TypeUserOnline:
		fm.handleUserOnline(peer, env, raw)
	case TypeUserOffline:
		fm.handleUserOffline(peer, env, raw)
	case TypeNickChange:
		fm.handleNickChange(peer, env, raw)
	case TypeJoin:
		fm.handleJoin(peer, env, raw)
	case TypePart:
		fm.handlePart(peer, env, raw)
	case TypeKick:
		fm.handleKick(peer, env, raw)
	case TypeMode:
		fm.handleMode(peer, env, raw)
	case TypeTopic:
		fm.handleTopic(peer, env, raw)
	case TypeChannelMessage:
		fm.handleChannelMessage(peer, env, raw)
	case TypePrivateMessage:
		fm.handlePrivateMessage(peer, env, raw)
	case TypeNotice:
		fm.handleNotice(peer, env, raw)
	case TypeSyncRequest:
		fm.handleSyncRequest(peer, env, raw)
	case TypeSyncResponse:
		fm.handleSyncResponse(peer, env, raw)
	case TypeIdentityUpdate:
		fm.handleIdentityUpdate(peer, env, raw)
	case TypeError:
		fm.handleError(peer, env, raw)
	default:
		log.Printf("federation: unknown message type %s from %s", env.Type, peer.Hostname)
	}

	// Forward to other peers (flood routing)
	fm.forwardToPeers(peer, raw)
}

// forwardToPeers forwards a message to all connected peers except the source
func (fm *FederationManager) forwardToPeers(source *PeerConnection, raw map[string]interface{}) {
	data, err := json.Marshal(raw)
	if err != nil {
		return
	}
	fm.peers.BroadcastExcept(data, source.Hostname)
}

// sendHello sends a Hello message to a peer
func (fm *FederationManager) sendHello(peer *PeerConnection) {
	env := NewEnvelope(TypeHello, fm.serverURN, fm.clock)
	env.Payload["caps"] = fm.caps
	env.Payload["vector"] = fm.clock.GetVector()

	if err := Sign(env, fm.privKey); err != nil {
		log.Printf("federation: failed to sign Hello: %v", err)
		return
	}

	if err := peer.SendEnvelope(env); err != nil {
		log.Printf("federation: failed to send Hello to %s: %v", peer.Hostname, err)
	}
}

// handleHello processes a Hello message
func (fm *FederationManager) handleHello(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	// Extract capabilities
	if caps, ok := raw["caps"].([]interface{}); ok {
		capStrs := make([]string, 0, len(caps))
		for _, c := range caps {
			if s, ok := c.(string); ok {
				capStrs = append(capStrs, s)
			}
		}
		peer.SetCaps(capStrs)
	}

	// Extract vector
	if vector, ok := raw["vector"].(map[string]interface{}); ok {
		v := make(map[string]int64)
		for k, val := range vector {
			if f, ok := val.(float64); ok {
				v[k] = int64(f)
			}
		}
		peer.UpdateVector(v)
	}

	// Mark peer as syncing
	peer.setState(PeerStateSyncing)

	// Send our Hello in response if this is first contact
	if peer.State() == PeerStateSyncing {
		fm.sendHello(peer)
	}

	// Determine what events they need
	fm.sendSyncResponse(peer, peer.GetVector())

	// Send our current users
	fm.sendLocalUsers(peer)

	// Mark peer as ready
	peer.setState(PeerStateReady)
	log.Printf("federation: peer %s is now ready", peer.Hostname)
}

// sendSyncResponse sends missing events to a peer
func (fm *FederationManager) sendSyncResponse(peer *PeerConnection, theirVector map[string]int64) {
	env := NewEnvelope(TypeSyncResponse, fm.serverURN, fm.clock)

	var events []json.RawMessage

	// Get events they're missing from our origin
	ourSeq := theirVector[fm.serverURN]
	for _, data := range fm.eventStore.GetEventsSince(fm.serverURN, ourSeq) {
		events = append(events, json.RawMessage(data))
	}

	// Get events from other origins they might be missing
	for origin := range fm.clock.GetVector() {
		if origin == fm.serverURN {
			continue
		}
		theirSeq := theirVector[origin]
		for _, data := range fm.eventStore.GetEventsSince(origin, theirSeq) {
			events = append(events, json.RawMessage(data))
		}
	}

	if len(events) > 0 {
		env.Payload["events"] = events
	}

	if err := Sign(env, fm.privKey); err != nil {
		log.Printf("federation: failed to sign SyncResponse: %v", err)
		return
	}

	if err := peer.SendEnvelope(env); err != nil {
		log.Printf("federation: failed to send SyncResponse to %s: %v", peer.Hostname, err)
	}
}

// sendLocalUsers sends UserOnline for all local users to a peer
func (fm *FederationManager) sendLocalUsers(peer *PeerConnection) {
	fm.server.mu.RLock()
	clients := make([]*Client, 0, len(fm.server.clients))
	for _, c := range fm.server.clients {
		if c.registered {
			clients = append(clients, c)
		}
	}
	fm.server.mu.RUnlock()

	for _, c := range clients {
		fm.BroadcastUserOnline(c)
	}
}

// handlePing processes a Ping message
func (fm *FederationManager) handlePing(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	nonce, _ := raw["nonce"].(string)
	fm.sendPong(peer, nonce)
}

// sendPong sends a Pong response
func (fm *FederationManager) sendPong(peer *PeerConnection, nonce string) {
	env := NewEnvelope(TypePong, fm.serverURN, fm.clock)
	env.Payload["nonce"] = nonce

	if err := Sign(env, fm.privKey); err != nil {
		log.Printf("federation: failed to sign Pong: %v", err)
		return
	}

	if err := peer.SendEnvelope(env); err != nil {
		log.Printf("federation: failed to send Pong to %s: %v", peer.Hostname, err)
	}
}

// handlePong processes a Pong message
func (fm *FederationManager) handlePong(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	nonce, _ := raw["nonce"].(string)
	peer.HandlePong(nonce)
}

// handleUserOnline processes a UserOnline message
//
// Security: We verify that the user belongs to the originating server before
// accepting identity claims. The originating server is trusted to have verified
// the cryptographic proof for identities it broadcasts.
func (fm *FederationManager) handleUserOnline(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	userMap, ok := raw["user"].(map[string]interface{})
	if !ok {
		return
	}

	userURN, _ := userMap["@id"].(string)
	nick, _ := userMap["nick"].(string)
	ident, _ := userMap["ident"].(string)
	host, _ := userMap["host"].(string)
	realname, _ := userMap["realname"].(string)

	// Verify the message origin owns this user (prevent server A from
	// announcing users homed on server B)
	if !fm.isUserOwnedByOrigin(userURN, env.Origin) {
		log.Printf("federation: rejected UserOnline for %s from non-home server %s", userURN, env.Origin)
		fm.sendError(peer, ErrUnknownOrigin, "cannot announce user on different server", env.ID)
		return
	}

	// Extract identity if present (trusted because we verified origin above)
	var identity, did string
	if identityData, ok := userMap["identity"]; ok && identityData != nil {
		if identityMap, ok := identityData.(map[string]interface{}); ok {
			if data, err := json.Marshal(identityMap); err == nil {
				identity = string(data)
			}
			if didStr, ok := identityMap["id"].(string); ok {
				did = didStr
			}
		}
	}

	// Extract server from user URN
	parts := strings.Split(userURN, ":")
	server := ""
	if len(parts) >= 4 {
		server = parts[3]
	}

	// Check for nick collision
	if fm.checkNickCollision(nick, env.Seq, env.Origin) {
		log.Printf("federation: nick collision for %s, remote loses", nick)
		return
	}

	fm.mu.Lock()
	fm.remoteUsers[userURN] = &RemoteUser{
		URN:      userURN,
		Nick:     nick,
		Ident:    ident,
		Host:     host,
		Realname: realname,
		Server:   server,
		Seq:      env.Seq,
		Origin:   env.Origin,
		Identity: identity,
		DID:      did,
	}
	fm.mu.Unlock()

	log.Printf("federation: remote user online: %s", nick)
}

// handleUserOffline processes a UserOffline message
func (fm *FederationManager) handleUserOffline(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	userURN, _ := raw["user"].(string)
	reason, _ := raw["reason"].(string)

	fm.mu.Lock()
	ru, ok := fm.remoteUsers[userURN]
	if ok {
		delete(fm.remoteUsers, userURN)
	}
	fm.mu.Unlock()

	if ok {
		log.Printf("federation: remote user offline: %s (%s)", ru.Nick, reason)

		// Notify local channels this user was in
		fm.notifyRemoteQuit(ru, reason)
	}
}

// handleNickChange processes a NickChange message
func (fm *FederationManager) handleNickChange(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	userURN, _ := raw["user"].(string)
	oldNick, _ := raw["oldNick"].(string)
	newNick, _ := raw["newNick"].(string)

	// Check for nick collision with new nick
	if fm.checkNickCollision(newNick, env.Seq, env.Origin) {
		log.Printf("federation: nick collision for %s on nick change", newNick)
		return
	}

	fm.mu.Lock()
	if ru, ok := fm.remoteUsers[userURN]; ok {
		ru.Nick = newNick
		// Update URN
		newURN := MakeUserURN(ru.Server, newNick)
		delete(fm.remoteUsers, userURN)
		ru.URN = newURN
		fm.remoteUsers[newURN] = ru
	}
	fm.mu.Unlock()

	// Notify local clients in shared channels
	fm.notifyRemoteNickChange(oldNick, newNick)
}

// handleJoin processes a Join message
func (fm *FederationManager) handleJoin(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	userURN, _ := raw["user"].(string)
	channelURN, _ := raw["channel"].(string)
	modes, _ := raw["modes"].(string)

	// Get remote user
	fm.mu.RLock()
	ru := fm.remoteUsers[userURN]
	fm.mu.RUnlock()

	if ru == nil {
		log.Printf("federation: unknown user %s joining channel", userURN)
		return
	}

	// Extract channel name from URN
	channelName := extractChannelName(channelURN)

	// Get or create channel
	ch := fm.server.getOrCreateChannel("#" + channelName)

	// Send remote join event to channel
	ch.events <- evRemoteJoin{
		user:  ru,
		modes: modes,
	}
}

// handlePart processes a Part message
func (fm *FederationManager) handlePart(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	userURN, _ := raw["user"].(string)
	channelURN, _ := raw["channel"].(string)
	reason, _ := raw["reason"].(string)

	fm.mu.RLock()
	ru := fm.remoteUsers[userURN]
	fm.mu.RUnlock()

	if ru == nil {
		return
	}

	channelName := extractChannelName(channelURN)
	ch := fm.server.getChannel("#" + channelName)
	if ch == nil {
		return
	}

	ch.events <- evRemotePart{
		user:   ru,
		reason: reason,
	}
}

// handleKick processes a Kick message
func (fm *FederationManager) handleKick(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	channelURN, _ := raw["channel"].(string)
	userURN, _ := raw["user"].(string)
	byURN, _ := raw["by"].(string)
	reason, _ := raw["reason"].(string)

	fm.mu.RLock()
	target := fm.remoteUsers[userURN]
	kicker := fm.remoteUsers[byURN]
	fm.mu.RUnlock()

	channelName := extractChannelName(channelURN)
	ch := fm.server.getChannel("#" + channelName)
	if ch == nil {
		return
	}

	ch.events <- evRemoteKick{
		target:      target,
		targetURN:   userURN,
		kicker:      kicker,
		kickerURN:   byURN,
		reason:      reason,
	}
}

// handleMode processes a Mode message
func (fm *FederationManager) handleMode(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	channelURN, _ := raw["channel"].(string)
	byURN, _ := raw["by"].(string)
	changes, _ := raw["changes"].(string)

	fm.mu.RLock()
	by := fm.remoteUsers[byURN]
	fm.mu.RUnlock()

	channelName := extractChannelName(channelURN)
	ch := fm.server.getChannel("#" + channelName)
	if ch == nil {
		return
	}

	ch.events <- evRemoteMode{
		by:      by,
		byURN:   byURN,
		changes: changes,
	}
}

// handleTopic processes a Topic message
func (fm *FederationManager) handleTopic(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	channelURN, _ := raw["channel"].(string)
	byURN, _ := raw["by"].(string)
	topic, _ := raw["topic"].(string)

	fm.mu.RLock()
	by := fm.remoteUsers[byURN]
	fm.mu.RUnlock()

	channelName := extractChannelName(channelURN)
	ch := fm.server.getChannel("#" + channelName)
	if ch == nil {
		return
	}

	ch.events <- evRemoteTopic{
		by:    by,
		byURN: byURN,
		topic: topic,
		ts:    time.Now(),
	}
}

// handleChannelMessage processes a ChannelMessage
func (fm *FederationManager) handleChannelMessage(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	channelURN, _ := raw["channel"].(string)
	fromURN, _ := raw["from"].(string)
	text, _ := raw["text"].(string)

	fm.mu.RLock()
	from := fm.remoteUsers[fromURN]
	fm.mu.RUnlock()

	if from == nil {
		return
	}

	channelName := extractChannelName(channelURN)
	ch := fm.server.getChannel("#" + channelName)
	if ch == nil {
		return
	}

	ch.events <- evRemoteMessage{
		from:     from,
		text:     text,
		isNotice: false,
		msgID:    env.ID,
		time:     env.Ts,
	}
}

// handlePrivateMessage processes a PrivateMessage
func (fm *FederationManager) handlePrivateMessage(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	fromURN, _ := raw["from"].(string)
	toURN, _ := raw["to"].(string)
	text, _ := raw["text"].(string)

	fm.mu.RLock()
	from := fm.remoteUsers[fromURN]
	fm.mu.RUnlock()

	if from == nil {
		return
	}

	// Extract target nick from URN
	parts := strings.Split(toURN, ":")
	if len(parts) < 5 {
		return
	}
	targetNick := parts[4]

	// Find local client
	target := fm.server.getClient(targetNick)
	if target == nil {
		return
	}

	// Send to local client
	tags := make(map[string]string)
	if target.caps["message-ids"] {
		tags["msgid"] = env.ID
	}
	if target.caps["server-time"] {
		tags["time"] = env.Ts
	}

	line := fmt.Sprintf(":%s PRIVMSG %s :%s", from.Prefix(), target.Nick(), text)
	fm.server.ircv3.SendWithTags(target, tags, line)
}

// handleNotice processes a Notice message
func (fm *FederationManager) handleNotice(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	channelURN, _ := raw["channel"].(string)
	fromURN, _ := raw["from"].(string)
	toURN, _ := raw["to"].(string)
	text, _ := raw["text"].(string)

	fm.mu.RLock()
	from := fm.remoteUsers[fromURN]
	fm.mu.RUnlock()

	if from == nil {
		return
	}

	if channelURN != "" {
		// Channel notice
		channelName := extractChannelName(channelURN)
		ch := fm.server.getChannel("#" + channelName)
		if ch == nil {
			return
		}

		ch.events <- evRemoteMessage{
			from:     from,
			text:     text,
			isNotice: true,
			msgID:    env.ID,
			time:     env.Ts,
		}
	} else if toURN != "" {
		// Private notice
		parts := strings.Split(toURN, ":")
		if len(parts) < 5 {
			return
		}
		targetNick := parts[4]

		target := fm.server.getClient(targetNick)
		if target == nil {
			return
		}

		tags := make(map[string]string)
		if target.caps["message-ids"] {
			tags["msgid"] = env.ID
		}
		if target.caps["server-time"] {
			tags["time"] = env.Ts
		}

		line := fmt.Sprintf(":%s NOTICE %s :%s", from.Prefix(), target.Nick(), text)
		fm.server.ircv3.SendWithTags(target, tags, line)
	}
}

// handleSyncRequest processes a SyncRequest message
func (fm *FederationManager) handleSyncRequest(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	vector := make(map[string]int64)
	if v, ok := raw["vector"].(map[string]interface{}); ok {
		for k, val := range v {
			if f, ok := val.(float64); ok {
				vector[k] = int64(f)
			}
		}
	}

	fm.sendSyncResponse(peer, vector)
}

// handleSyncResponse processes a SyncResponse message
func (fm *FederationManager) handleSyncResponse(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	// Process events
	if events, ok := raw["events"].([]interface{}); ok {
		for _, ev := range events {
			if evMap, ok := ev.(map[string]interface{}); ok {
				var evEnv Envelope
				data, _ := json.Marshal(evMap)
				if json.Unmarshal(data, &evEnv) == nil {
					// Process this event if not duplicate
					if !fm.dedupe.IsDuplicate(evEnv.ID) {
						fm.handlePeerMessage(peer, &evEnv, evMap)
					}
				}
			}
		}
	}

	// Process full sync data if present
	if users, ok := raw["users"].([]interface{}); ok {
		fm.processFullSyncUsers(peer, users)
	}
	if channels, ok := raw["channels"].([]interface{}); ok {
		fm.processFullSyncChannels(peer, channels)
	}
}

// processFullSyncUsers processes users from a full sync
//
// Security: We verify that each user belongs to the peer's server before
// accepting identity claims. A server can only sync users it owns.
func (fm *FederationManager) processFullSyncUsers(peer *PeerConnection, users []interface{}) {
	peerOriginURN := MakeServerURN(peer.Hostname)

	for _, u := range users {
		uMap, ok := u.(map[string]interface{})
		if !ok {
			continue
		}

		userURN, _ := uMap["@id"].(string)
		nick, _ := uMap["nick"].(string)
		ident, _ := uMap["ident"].(string)
		host, _ := uMap["host"].(string)
		realname, _ := uMap["realname"].(string)

		// Verify the peer owns this user (prevent server A from syncing
		// users homed on server B)
		if !fm.isUserOwnedByOrigin(userURN, peerOriginURN) {
			log.Printf("federation: rejected sync user %s from non-home server %s", userURN, peer.Hostname)
			continue
		}

		// Extract identity if present (trusted because we verified origin above)
		var identity, did string
		if identityData, ok := uMap["identity"]; ok && identityData != nil {
			if identityMap, ok := identityData.(map[string]interface{}); ok {
				if data, err := json.Marshal(identityMap); err == nil {
					identity = string(data)
				}
				if didStr, ok := identityMap["id"].(string); ok {
					did = didStr
				}
			}
		}

		parts := strings.Split(userURN, ":")
		server := ""
		if len(parts) >= 4 {
			server = parts[3]
		}

		fm.mu.Lock()
		fm.remoteUsers[userURN] = &RemoteUser{
			URN:      userURN,
			Nick:     nick,
			Ident:    ident,
			Host:     host,
			Realname: realname,
			Server:   server,
			Identity: identity,
			DID:      did,
		}
		fm.mu.Unlock()
	}
}

// processFullSyncChannels processes channels from a full sync
func (fm *FederationManager) processFullSyncChannels(peer *PeerConnection, channels []interface{}) {
	// Channel state merge: union of members, ops/voice, bans; latest topic/modes
	for _, ch := range channels {
		chMap, ok := ch.(map[string]interface{})
		if !ok {
			continue
		}

		channelURN, _ := chMap["@id"].(string)
		channelName := "#" + extractChannelName(channelURN)
		topic, _ := chMap["topic"].(string)
		topicBy, _ := chMap["topicBy"].(string)
		topicTs, _ := chMap["topicTs"].(string)
		modes, _ := chMap["modes"].(string)

		channel := fm.server.getOrCreateChannel(channelName)

		// Send merge event to channel actor
		channel.events <- evRemoteMerge{
			topic:   topic,
			topicBy: topicBy,
			topicTs: topicTs,
			modes:   modes,
			members: chMap["members"],
			bans:    chMap["bans"],
		}
	}
}

// handleError processes an Error message
func (fm *FederationManager) handleError(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	code, _ := raw["code"].(string)
	message, _ := raw["message"].(string)
	ref, _ := raw["ref"].(string)

	log.Printf("federation: error from %s: %s - %s (ref: %s)", peer.Hostname, code, message, ref)
}

// sendError sends an error message to a peer
func (fm *FederationManager) sendError(peer *PeerConnection, code, message, ref string) {
	env := NewEnvelope(TypeError, fm.serverURN, fm.clock)
	env.Payload["code"] = code
	env.Payload["message"] = message
	if ref != "" {
		env.Payload["ref"] = ref
	}

	if err := Sign(env, fm.privKey); err != nil {
		return
	}

	_ = peer.SendEnvelope(env)
}

// checkNickCollision checks if a nick collides with a local or known remote user
// Returns true if there's a collision and the remote user should lose
func (fm *FederationManager) checkNickCollision(nick string, remoteSeq int64, remoteOrigin string) bool {
	// Check against local users
	localClient := fm.server.getClient(nick)
	if localClient != nil {
		// Collision with local user
		// Local always wins for now (could implement (seq, origin) comparison)
		return true
	}

	// Check against known remote users
	fm.mu.RLock()
	for _, ru := range fm.remoteUsers {
		if strings.EqualFold(ru.Nick, nick) {
			// Compare (seq, origin) - lower wins
			cmp := Compare(ru.Seq, ru.Origin, remoteSeq, remoteOrigin)
			fm.mu.RUnlock()
			return cmp < 0 // existing user has lower tuple, new user loses
		}
	}
	fm.mu.RUnlock()

	return false
}

// removeUsersFromServer removes all remote users from a specific server
func (fm *FederationManager) removeUsersFromServer(hostname string) {
	fm.mu.Lock()
	var toRemove []string
	for urn, ru := range fm.remoteUsers {
		if ru.Server == hostname {
			toRemove = append(toRemove, urn)
		}
	}
	for _, urn := range toRemove {
		delete(fm.remoteUsers, urn)
	}
	fm.mu.Unlock()
}

// notifyRemoteQuit notifies local channels about a remote user quitting
func (fm *FederationManager) notifyRemoteQuit(ru *RemoteUser, reason string) {
	fm.server.mu.RLock()
	chans := make([]*Channel, 0, len(fm.server.channels))
	for _, ch := range fm.server.channels {
		chans = append(chans, ch)
	}
	fm.server.mu.RUnlock()

	for _, ch := range chans {
		ch.events <- evRemoteQuit{
			user:   ru,
			reason: reason,
		}
	}
}

// notifyRemoteNickChange notifies local channels about a remote nick change
func (fm *FederationManager) notifyRemoteNickChange(oldNick, newNick string) {
	fm.server.mu.RLock()
	chans := make([]*Channel, 0, len(fm.server.channels))
	for _, ch := range fm.server.channels {
		chans = append(chans, ch)
	}
	fm.server.mu.RUnlock()

	for _, ch := range chans {
		ch.events <- evRemoteNickChange{
			oldNick: oldNick,
			newNick: newNick,
		}
	}
}

// BroadcastUserOnline broadcasts a user coming online
func (fm *FederationManager) BroadcastUserOnline(c *Client) {
	env := NewEnvelope(TypeUserOnline, fm.serverURN, fm.clock)

	c.mu.RLock()
	identity := c.identity
	c.mu.RUnlock()

	userPayload := map[string]interface{}{
		"@type":    "User",
		"@id":      MakeUserURN(fm.hostname, c.Nick()),
		"nick":     c.Nick(),
		"ident":    c.user,
		"host":     c.hostname,
		"realname": c.realname,
	}

	// Include identity if set
	if identity != "" {
		var identityDoc interface{}
		if err := json.Unmarshal([]byte(identity), &identityDoc); err == nil {
			userPayload["identity"] = identityDoc
		}
	}

	env.Payload["user"] = userPayload

	fm.broadcastEnvelope(env)
}

// BroadcastUserOffline broadcasts a user going offline
func (fm *FederationManager) BroadcastUserOffline(c *Client, reason string) {
	env := NewEnvelope(TypeUserOffline, fm.serverURN, fm.clock)
	env.Payload["user"] = MakeUserURN(fm.hostname, c.Nick())
	if reason != "" {
		env.Payload["reason"] = reason
	}

	fm.broadcastEnvelope(env)
}

// BroadcastNickChange broadcasts a nick change
func (fm *FederationManager) BroadcastNickChange(c *Client, oldNick, newNick string) {
	env := NewEnvelope(TypeNickChange, fm.serverURN, fm.clock)
	env.Payload["user"] = MakeUserURN(fm.hostname, oldNick)
	env.Payload["oldNick"] = oldNick
	env.Payload["newNick"] = newNick

	fm.broadcastEnvelope(env)
}

// BroadcastJoin broadcasts a channel join
func (fm *FederationManager) BroadcastJoin(c *Client, channelName, modes string) {
	env := NewEnvelope(TypeJoin, fm.serverURN, fm.clock)
	env.Payload["user"] = MakeUserURN(fm.hostname, c.Nick())
	env.Payload["channel"] = MakeChannelURN(channelName)
	if modes != "" {
		env.Payload["modes"] = modes
	}

	fm.broadcastEnvelope(env)
}

// BroadcastPart broadcasts a channel part
func (fm *FederationManager) BroadcastPart(c *Client, channelName, reason string) {
	env := NewEnvelope(TypePart, fm.serverURN, fm.clock)
	env.Payload["user"] = MakeUserURN(fm.hostname, c.Nick())
	env.Payload["channel"] = MakeChannelURN(channelName)
	if reason != "" {
		env.Payload["reason"] = reason
	}

	fm.broadcastEnvelope(env)
}

// BroadcastKick broadcasts a kick
func (fm *FederationManager) BroadcastKick(kicker, target *Client, channelName, reason string) {
	env := NewEnvelope(TypeKick, fm.serverURN, fm.clock)
	env.Payload["channel"] = MakeChannelURN(channelName)
	env.Payload["user"] = MakeUserURN(fm.hostname, target.Nick())
	env.Payload["by"] = MakeUserURN(fm.hostname, kicker.Nick())
	if reason != "" {
		env.Payload["reason"] = reason
	}

	fm.broadcastEnvelope(env)
}

// BroadcastMode broadcasts a mode change
func (fm *FederationManager) BroadcastMode(c *Client, channelName, changes string) {
	env := NewEnvelope(TypeMode, fm.serverURN, fm.clock)
	env.Payload["channel"] = MakeChannelURN(channelName)
	env.Payload["by"] = MakeUserURN(fm.hostname, c.Nick())
	env.Payload["changes"] = changes

	fm.broadcastEnvelope(env)
}

// BroadcastTopic broadcasts a topic change
func (fm *FederationManager) BroadcastTopic(c *Client, channelName, topic string) {
	env := NewEnvelope(TypeTopic, fm.serverURN, fm.clock)
	env.Payload["channel"] = MakeChannelURN(channelName)
	env.Payload["by"] = MakeUserURN(fm.hostname, c.Nick())
	env.Payload["topic"] = topic

	fm.broadcastEnvelope(env)
}

// BroadcastChannelMessage broadcasts a channel message
func (fm *FederationManager) BroadcastChannelMessage(c *Client, channelName, text string) {
	env := NewEnvelope(TypeChannelMessage, fm.serverURN, fm.clock)
	env.Payload["channel"] = MakeChannelURN(channelName)
	env.Payload["from"] = MakeUserURN(fm.hostname, c.Nick())
	env.Payload["text"] = text

	fm.broadcastEnvelope(env)
}

// BroadcastPrivateMessage broadcasts a private message
func (fm *FederationManager) BroadcastPrivateMessage(from *Client, toURN, text string) {
	env := NewEnvelope(TypePrivateMessage, fm.serverURN, fm.clock)
	env.Payload["from"] = MakeUserURN(fm.hostname, from.Nick())
	env.Payload["to"] = toURN
	env.Payload["text"] = text

	fm.broadcastEnvelope(env)
}

// BroadcastNotice broadcasts a notice
func (fm *FederationManager) BroadcastNotice(from *Client, channelURN, toURN, text string) {
	env := NewEnvelope(TypeNotice, fm.serverURN, fm.clock)
	env.Payload["from"] = MakeUserURN(fm.hostname, from.Nick())
	if channelURN != "" {
		env.Payload["channel"] = channelURN
	}
	if toURN != "" {
		env.Payload["to"] = toURN
	}
	env.Payload["text"] = text

	fm.broadcastEnvelope(env)
}

// BroadcastIdentityUpdate broadcasts an identity set or clear
func (fm *FederationManager) BroadcastIdentityUpdate(c *Client, identityJSON string) {
	env := NewEnvelope(TypeIdentityUpdate, fm.serverURN, fm.clock)
	env.Payload["user"] = MakeUserURN(fm.hostname, c.Nick())

	if identityJSON == "" {
		// Clear identity
		env.Payload["identity"] = nil
	} else {
		// Parse and include identity document
		var identity interface{}
		if err := json.Unmarshal([]byte(identityJSON), &identity); err != nil {
			// Corrupted identity data should not be broadcast
			log.Printf("federation: failed to parse identity JSON for broadcast: %v", err)
			return
		}
		env.Payload["identity"] = identity
	}

	fm.broadcastEnvelope(env)
}

// handleIdentityUpdate processes an IdentityUpdate message
//
// Security: Identity claims are trusted per-server. We verify that the message
// origin matches the user's home server (server A cannot claim identities for
// users on server B). The originating server is responsible for verifying the
// cryptographic proof before broadcasting the identity.
func (fm *FederationManager) handleIdentityUpdate(peer *PeerConnection, env *Envelope, raw map[string]interface{}) {
	userURN, _ := raw["user"].(string)

	// Verify the message origin owns this user (prevent server A from claiming
	// identities for users homed on server B)
	if !fm.isUserOwnedByOrigin(userURN, env.Origin) {
		log.Printf("federation: rejected identity update for %s from non-home server %s", userURN, env.Origin)
		fm.sendError(peer, ErrUnknownOrigin, "cannot update identity for user on different server", env.ID)
		return
	}

	fm.mu.Lock()
	ru, ok := fm.remoteUsers[userURN]
	if !ok {
		fm.mu.Unlock()
		log.Printf("federation: identity update for unknown user %s", userURN)
		return
	}

	// Extract identity (can be null, object, or string)
	identity := raw["identity"]

	if identity == nil {
		// Identity cleared
		ru.Identity = ""
		ru.DID = ""
		nick := ru.Nick
		fm.mu.Unlock()
		log.Printf("federation: remote user %s cleared identity", nick)
	} else {
		// Identity set
		if identityMap, ok := identity.(map[string]interface{}); ok {
			// Extract DID from identity document
			if did, ok := identityMap["id"].(string); ok {
				ru.DID = did
			}
			// Store as JSON string
			if data, err := json.Marshal(identityMap); err == nil {
				ru.Identity = string(data)
			}
		} else if identityStr, ok := identity.(string); ok {
			ru.Identity = identityStr
			// Try to parse and extract DID
			var doc map[string]interface{}
			if json.Unmarshal([]byte(identityStr), &doc) == nil {
				if did, ok := doc["id"].(string); ok {
					ru.DID = did
				}
			}
		}
		nick := ru.Nick
		did := ru.DID
		fm.mu.Unlock()
		log.Printf("federation: remote user %s set identity DID=%s", nick, did)
	}
}

// broadcastEnvelope signs and broadcasts an envelope to all peers
func (fm *FederationManager) broadcastEnvelope(env *Envelope) {
	if err := Sign(env, fm.privKey); err != nil {
		log.Printf("federation: failed to sign envelope: %v", err)
		return
	}

	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("federation: failed to marshal envelope: %v", err)
		return
	}

	// Store event for delta sync
	fm.eventStore.Store(env.ID, env.Seq, env.Origin, data)

	// Broadcast to all peers
	fm.peers.Broadcast(data)
}

// GetRemoteUser returns a remote user by nick
func (fm *FederationManager) GetRemoteUser(nick string) *RemoteUser {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	for _, ru := range fm.remoteUsers {
		if strings.EqualFold(ru.Nick, nick) {
			return ru
		}
	}
	return nil
}

// IsRemoteUser checks if a nick belongs to a remote user
func (fm *FederationManager) IsRemoteUser(nick string) bool {
	return fm.GetRemoteUser(nick) != nil
}

// extractChannelName extracts channel name from URN
// e.g., "urn:irc:channel:foo" -> "foo"
func extractChannelName(urn string) string {
	const prefix = "urn:irc:channel:"
	if strings.HasPrefix(urn, prefix) {
		return urn[len(prefix):]
	}
	return urn
}

// isUserOwnedByOrigin checks if a user URN belongs to the given origin server.
// This prevents server A from making claims about users homed on server B.
// User URN format: urn:irc:user:<server>:<nick>
// Server URN format: urn:irc:server:<server>
func (fm *FederationManager) isUserOwnedByOrigin(userURN, originURN string) bool {
	// Extract server from user URN: urn:irc:user:<server>:<nick>
	userParts := strings.Split(userURN, ":")
	if len(userParts) < 4 {
		return false
	}
	userServer := userParts[3]

	// Extract server from origin URN: urn:irc:server:<server>
	originParts := strings.Split(originURN, ":")
	if len(originParts) < 4 {
		return false
	}
	originServer := originParts[3]

	return strings.EqualFold(userServer, originServer)
}

// Remote event types for channel actor
type evRemoteJoin struct {
	user  *RemoteUser
	modes string
}

type evRemotePart struct {
	user   *RemoteUser
	reason string
}

type evRemoteQuit struct {
	user   *RemoteUser
	reason string
}

type evRemoteKick struct {
	target      *RemoteUser
	targetURN   string
	kicker      *RemoteUser
	kickerURN   string
	reason      string
}

type evRemoteMode struct {
	by      *RemoteUser
	byURN   string
	changes string
}

type evRemoteTopic struct {
	by    *RemoteUser
	byURN string
	topic string
	ts    time.Time
}

type evRemoteMessage struct {
	from     *RemoteUser
	text     string
	isNotice bool
	msgID    string
	time     string
}

type evRemoteNickChange struct {
	oldNick string
	newNick string
}

type evRemoteMerge struct {
	topic   string
	topicBy string
	topicTs string
	modes   string
	members interface{}
	bans    interface{}
}

// Implement chanEvent interface for remote events
func (ev evRemoteJoin) handle(ch *Channel)       { handleRemoteJoin(ch, ev) }
func (ev evRemotePart) handle(ch *Channel)       { handleRemotePart(ch, ev) }
func (ev evRemoteQuit) handle(ch *Channel)       { handleRemoteQuit(ch, ev) }
func (ev evRemoteKick) handle(ch *Channel)       { handleRemoteKick(ch, ev) }
func (ev evRemoteMode) handle(ch *Channel)       { handleRemoteMode(ch, ev) }
func (ev evRemoteTopic) handle(ch *Channel)      { handleRemoteTopic(ch, ev) }
func (ev evRemoteMessage) handle(ch *Channel)    { handleRemoteMessage(ch, ev) }
func (ev evRemoteNickChange) handle(ch *Channel) { handleRemoteNickChange(ch, ev) }
func (ev evRemoteMerge) handle(ch *Channel)      { handleRemoteMerge(ch, ev) }

// Remote event handlers
func handleRemoteJoin(ch *Channel, ev evRemoteJoin) {
	if ev.user == nil {
		return
	}

	// Check if already a member
	if _, exists := ch.remoteMembers[ev.user.URN]; exists {
		return
	}

	// Store remote member
	ch.remoteMembers[ev.user.URN] = ev.user

	// Broadcast join to local members
	joinMsg := fmt.Sprintf(":%s JOIN %s", ev.user.Prefix(), ch.name)
	for member := range ch.members {
		member.Send(joinMsg)
	}

	log.Printf("federation: remote user %s joined %s", ev.user.Nick, ch.name)
}

func handleRemotePart(ch *Channel, ev evRemotePart) {
	if ev.user == nil {
		return
	}

	// Remove from remote members
	delete(ch.remoteMembers, ev.user.URN)

	partMsg := fmt.Sprintf(":%s PART %s", ev.user.Prefix(), ch.name)
	if ev.reason != "" {
		partMsg += " :" + ev.reason
	}
	for member := range ch.members {
		member.Send(partMsg)
	}
}

func handleRemoteQuit(ch *Channel, ev evRemoteQuit) {
	if ev.user == nil {
		return
	}

	// Remove from remote members
	delete(ch.remoteMembers, ev.user.URN)

	quitMsg := fmt.Sprintf(":%s QUIT :%s", ev.user.Prefix(), ev.reason)
	for member := range ch.members {
		member.Send(quitMsg)
	}
}

func handleRemoteKick(ch *Channel, ev evRemoteKick) {
	var kickerPrefix string
	if ev.kicker != nil {
		kickerPrefix = ev.kicker.Prefix()
	} else {
		// Extract nick from URN for display
		parts := strings.Split(ev.kickerURN, ":")
		if len(parts) >= 5 {
			kickerPrefix = parts[4] + "!unknown@unknown"
		} else {
			kickerPrefix = "unknown!unknown@unknown"
		}
	}

	var targetNick string
	if ev.target != nil {
		targetNick = ev.target.Nick
	} else {
		parts := strings.Split(ev.targetURN, ":")
		if len(parts) >= 5 {
			targetNick = parts[4]
		}
	}

	// Remove kicked user from remote members
	if ev.targetURN != "" {
		delete(ch.remoteMembers, ev.targetURN)
	}

	kickMsg := fmt.Sprintf(":%s KICK %s %s :%s", kickerPrefix, ch.name, targetNick, ev.reason)
	for member := range ch.members {
		member.Send(kickMsg)
	}
}

func handleRemoteMode(ch *Channel, ev evRemoteMode) {
	var byPrefix string
	if ev.by != nil {
		byPrefix = ev.by.Prefix()
	} else {
		parts := strings.Split(ev.byURN, ":")
		if len(parts) >= 5 {
			byPrefix = parts[4] + "!unknown@unknown"
		} else {
			byPrefix = "unknown!unknown@unknown"
		}
	}

	modeMsg := fmt.Sprintf(":%s MODE %s %s", byPrefix, ch.name, ev.changes)
	for member := range ch.members {
		member.Send(modeMsg)
	}
}

func handleRemoteTopic(ch *Channel, ev evRemoteTopic) {
	var byPrefix string
	if ev.by != nil {
		byPrefix = ev.by.Prefix()
	} else {
		parts := strings.Split(ev.byURN, ":")
		if len(parts) >= 5 {
			byPrefix = parts[4] + "!unknown@unknown"
		} else {
			byPrefix = "unknown!unknown@unknown"
		}
	}

	// Only update if newer (or we don't have timestamp comparison)
	ch.topic = ev.topic
	ch.topicWho = byPrefix
	ch.topicTime = ev.ts

	topicMsg := fmt.Sprintf(":%s TOPIC %s :%s", byPrefix, ch.name, ev.topic)
	for member := range ch.members {
		member.Send(topicMsg)
	}
}

func handleRemoteMessage(ch *Channel, ev evRemoteMessage) {
	if ev.from == nil {
		return
	}

	cmd := "PRIVMSG"
	if ev.isNotice {
		cmd = "NOTICE"
	}

	// Send to all local members with appropriate tags
	for member := range ch.members {
		tags := make(map[string]string)
		if member.caps["message-ids"] && ev.msgID != "" {
			tags["msgid"] = ev.msgID
		}
		if member.caps["server-time"] && ev.time != "" {
			tags["time"] = ev.time
		}

		line := fmt.Sprintf(":%s %s %s :%s", ev.from.Prefix(), cmd, ch.name, ev.text)
		ch.server.ircv3.SendWithTags(member, tags, line)
	}
}

func handleRemoteNickChange(ch *Channel, ev evRemoteNickChange) {
	msg := fmt.Sprintf(":%s!unknown@unknown NICK %s", ev.oldNick, ev.newNick)
	for member := range ch.members {
		member.Send(msg)
	}
}

func handleRemoteMerge(ch *Channel, ev evRemoteMerge) {
	// Channel state merge on partition heal
	// Topic: later timestamp wins
	if ev.topicTs != "" {
		remoteTime, err := time.Parse(time.RFC3339, ev.topicTs)
		if err == nil && remoteTime.After(ch.topicTime) {
			ch.topic = ev.topic
			ch.topicWho = ev.topicBy
			ch.topicTime = remoteTime
		}
	}

	// Modes: merge (later wins for conflicting modes)
	for _, m := range ev.modes {
		ch.modes[m] = true
	}

	// Bans: union
	if bans, ok := ev.bans.([]interface{}); ok {
		for _, b := range bans {
			if banMap, ok := b.(map[string]interface{}); ok {
				mask, _ := banMap["mask"].(string)
				by, _ := banMap["by"].(string)
				tsStr, _ := banMap["ts"].(string)
				ts, _ := time.Parse(time.RFC3339, tsStr)

				ch.bans[strings.ToLower(mask)] = banEntry{
					mask: mask,
					who:  by,
					when: ts,
				}
			}
		}
	}

	// Members: union handled by individual join events
	log.Printf("federation: merged state for channel %s", ch.name)
}
