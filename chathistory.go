package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Chat history constants
const (
	DefaultHistoryLimit  = 500
	MaxHistoryPerTarget  = 1000
	MaxHistoryRequestSize = 500
)

// StoredMessage represents a message stored in history
type StoredMessage struct {
	MsgID     string    // server/seq format
	Time      time.Time // server timestamp
	Prefix    string    // sender's prefix (nick!user@host)
	Account   string    // sender's account name
	DID       string    // sender's DID
	Command   string    // PRIVMSG or NOTICE
	Target    string    // channel or nick
	Text      string    // message content
	IsNotice  bool
}

// HistoryBuffer is a ring buffer for storing messages
type HistoryBuffer struct {
	messages []StoredMessage
	head     int  // next write position
	size     int  // current number of messages
	capacity int
}

func newHistoryBuffer(capacity int) *HistoryBuffer {
	return &HistoryBuffer{
		messages: make([]StoredMessage, capacity),
		capacity: capacity,
	}
}

func (b *HistoryBuffer) Add(msg StoredMessage) {
	b.messages[b.head] = msg
	b.head = (b.head + 1) % b.capacity
	if b.size < b.capacity {
		b.size++
	}
}

// GetAll returns all messages in chronological order (oldest first)
func (b *HistoryBuffer) GetAll() []StoredMessage {
	if b.size == 0 {
		return nil
	}

	result := make([]StoredMessage, b.size)
	if b.size < b.capacity {
		// Haven't wrapped yet
		copy(result, b.messages[:b.size])
	} else {
		// Wrapped, head points to oldest
		copy(result, b.messages[b.head:])
		copy(result[b.capacity-b.head:], b.messages[:b.head])
	}
	return result
}

// ChatHistoryStore manages message history for channels and DMs
type ChatHistoryStore struct {
	mu       sync.RWMutex
	channels map[string]*HistoryBuffer // lowercase channel -> buffer
	dms      map[string]*HistoryBuffer // sorted nick pair -> buffer
}

func newChatHistoryStore() *ChatHistoryStore {
	return &ChatHistoryStore{
		channels: make(map[string]*HistoryBuffer),
		dms:      make(map[string]*HistoryBuffer),
	}
}

// dmKey creates a canonical key for DM history between two nicks
func dmKey(nick1, nick2 string) string {
	n1 := strings.ToLower(nick1)
	n2 := strings.ToLower(nick2)
	if n1 < n2 {
		return n1 + ":" + n2
	}
	return n2 + ":" + n1
}

// StoreChannelMessage stores a message in channel history
func (s *ChatHistoryStore) StoreChannelMessage(msg StoredMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := strings.ToLower(msg.Target)
	buf, ok := s.channels[key]
	if !ok {
		buf = newHistoryBuffer(MaxHistoryPerTarget)
		s.channels[key] = buf
	}
	buf.Add(msg)
}

// StoreDMMessage stores a message in DM history
func (s *ChatHistoryStore) StoreDMMessage(sender, recipient string, msg StoredMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := dmKey(sender, recipient)
	buf, ok := s.dms[key]
	if !ok {
		buf = newHistoryBuffer(MaxHistoryPerTarget)
		s.dms[key] = buf
	}
	buf.Add(msg)
}

// GetChannelHistory returns messages for a channel
func (s *ChatHistoryStore) GetChannelHistory(channel string) []StoredMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	buf := s.channels[strings.ToLower(channel)]
	if buf == nil {
		return nil
	}
	return buf.GetAll()
}

// GetDMHistory returns messages between two users
func (s *ChatHistoryStore) GetDMHistory(nick1, nick2 string) []StoredMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	buf := s.dms[dmKey(nick1, nick2)]
	if buf == nil {
		return nil
	}
	return buf.GetAll()
}

// GetAllDMsForUser returns all DM history for a user (aggregated)
func (s *ChatHistoryStore) GetAllDMsForUser(nick string) []StoredMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nickLower := strings.ToLower(nick)
	var all []StoredMessage

	for key, buf := range s.dms {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) == 2 && (parts[0] == nickLower || parts[1] == nickLower) {
			all = append(all, buf.GetAll()...)
		}
	}

	// Sort by time
	sort.Slice(all, func(i, j int) bool {
		return all[i].Time.Before(all[j].Time)
	})

	return all
}

// ChatHistoryHandler handles CHATHISTORY commands
type ChatHistoryHandler struct {
	server   *Server
	store    *ChatHistoryStore
	ircv3    *IRCv3Handler
}

func newChatHistoryHandler(server *Server, store *ChatHistoryStore, ircv3 *IRCv3Handler) *ChatHistoryHandler {
	return &ChatHistoryHandler{
		server: server,
		store:  store,
		ircv3:  ircv3,
	}
}

// Handle processes CHATHISTORY commands
func (h *ChatHistoryHandler) Handle(c *Client, msg *Message, label string) {
	if len(msg.Params) < 3 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "CHATHISTORY :Not enough parameters")
		return
	}

	subcommand := strings.ToUpper(msg.Params[0])
	target := msg.Params[1]

	switch subcommand {
	case "LATEST":
		h.handleLatest(c, target, msg.Params[2:], label)
	case "BEFORE":
		h.handleBefore(c, target, msg.Params[2:], label)
	case "AFTER":
		h.handleAfter(c, target, msg.Params[2:], label)
	case "AROUND":
		h.handleAround(c, target, msg.Params[2:], label)
	case "BETWEEN":
		h.handleBetween(c, target, msg.Params[2:], label)
	default:
		c.SendNumeric(ERR_UNKNOWNCOMMAND, fmt.Sprintf("CHATHISTORY %s :Unknown subcommand", subcommand))
	}
}

// handleLatest handles CHATHISTORY LATEST
func (h *ChatHistoryHandler) handleLatest(c *Client, target string, params []string, label string) {
	if len(params) < 2 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "CHATHISTORY LATEST :Not enough parameters")
		return
	}

	reference := params[0]
	limit := parseLimit(params[1])

	messages := h.getHistory(c, target)
	if messages == nil {
		h.sendEmptyBatch(c, target, label)
		return
	}

	// If reference is *, get the latest messages
	// If reference is msgid=xxx, get messages before that
	var filtered []StoredMessage
	if reference == "*" {
		// Get most recent
		start := len(messages) - limit
		if start < 0 {
			start = 0
		}
		filtered = messages[start:]
	} else {
		// Get messages before the reference
		idx := h.findByReference(messages, reference)
		if idx == -1 {
			h.sendEmptyBatch(c, target, label)
			return
		}
		start := idx - limit
		if start < 0 {
			start = 0
		}
		filtered = messages[start:idx]
	}

	h.sendBatch(c, target, filtered, label)
}

// handleBefore handles CHATHISTORY BEFORE
func (h *ChatHistoryHandler) handleBefore(c *Client, target string, params []string, label string) {
	if len(params) < 2 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "CHATHISTORY BEFORE :Not enough parameters")
		return
	}

	reference := params[0]
	limit := parseLimit(params[1])

	messages := h.getHistory(c, target)
	if messages == nil {
		h.sendEmptyBatch(c, target, label)
		return
	}

	idx := h.findByReference(messages, reference)
	if idx == -1 {
		h.sendEmptyBatch(c, target, label)
		return
	}

	start := idx - limit
	if start < 0 {
		start = 0
	}
	filtered := messages[start:idx]

	h.sendBatch(c, target, filtered, label)
}

// handleAfter handles CHATHISTORY AFTER
func (h *ChatHistoryHandler) handleAfter(c *Client, target string, params []string, label string) {
	if len(params) < 2 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "CHATHISTORY AFTER :Not enough parameters")
		return
	}

	reference := params[0]
	limit := parseLimit(params[1])

	messages := h.getHistory(c, target)
	if messages == nil {
		h.sendEmptyBatch(c, target, label)
		return
	}

	idx := h.findByReference(messages, reference)
	if idx == -1 {
		h.sendEmptyBatch(c, target, label)
		return
	}

	start := idx + 1
	end := start + limit
	if end > len(messages) {
		end = len(messages)
	}
	if start >= len(messages) {
		h.sendEmptyBatch(c, target, label)
		return
	}
	filtered := messages[start:end]

	h.sendBatch(c, target, filtered, label)
}

// handleAround handles CHATHISTORY AROUND
func (h *ChatHistoryHandler) handleAround(c *Client, target string, params []string, label string) {
	if len(params) < 2 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "CHATHISTORY AROUND :Not enough parameters")
		return
	}

	reference := params[0]
	limit := parseLimit(params[1])

	messages := h.getHistory(c, target)
	if messages == nil {
		h.sendEmptyBatch(c, target, label)
		return
	}

	idx := h.findByReference(messages, reference)
	if idx == -1 {
		h.sendEmptyBatch(c, target, label)
		return
	}

	// Get half before, half after
	halfBefore := limit / 2
	halfAfter := limit - halfBefore

	start := idx - halfBefore
	if start < 0 {
		start = 0
	}
	end := idx + halfAfter + 1
	if end > len(messages) {
		end = len(messages)
	}
	filtered := messages[start:end]

	h.sendBatch(c, target, filtered, label)
}

// handleBetween handles CHATHISTORY BETWEEN
func (h *ChatHistoryHandler) handleBetween(c *Client, target string, params []string, label string) {
	if len(params) < 3 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "CHATHISTORY BETWEEN :Not enough parameters")
		return
	}

	startRef := params[0]
	endRef := params[1]
	limit := parseLimit(params[2])

	messages := h.getHistory(c, target)
	if messages == nil {
		h.sendEmptyBatch(c, target, label)
		return
	}

	startIdx := h.findByReference(messages, startRef)
	endIdx := h.findByReference(messages, endRef)

	if startIdx == -1 || endIdx == -1 {
		h.sendEmptyBatch(c, target, label)
		return
	}

	// Ensure correct order
	if startIdx > endIdx {
		startIdx, endIdx = endIdx, startIdx
	}

	// Exclude the boundary messages themselves
	startIdx++
	if startIdx > endIdx {
		h.sendEmptyBatch(c, target, label)
		return
	}

	filtered := messages[startIdx:endIdx]
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	h.sendBatch(c, target, filtered, label)
}

// getHistory retrieves history for a target, checking permissions
func (h *ChatHistoryHandler) getHistory(c *Client, target string) []StoredMessage {
	if isValidChannel(target) {
		// Channel history - check membership
		ch := h.server.getChannel(target)
		if ch == nil {
			c.SendNumeric(ERR_NOSUCHCHANNEL, fmt.Sprintf("%s :No such channel", target))
			return nil
		}
		// ponytail: for now, require membership; could add permission checks
		if !ch.isMember(c) {
			c.SendNumeric(ERR_NOTONCHANNEL, fmt.Sprintf("%s :You're not on that channel", target))
			return nil
		}
		return h.store.GetChannelHistory(target)
	} else if target == "*" {
		// All DMs for this user
		return h.store.GetAllDMsForUser(c.Nick())
	} else {
		// DM with specific user
		return h.store.GetDMHistory(c.Nick(), target)
	}
}

// findByReference finds a message by msgid or timestamp reference
func (h *ChatHistoryHandler) findByReference(messages []StoredMessage, ref string) int {
	if strings.HasPrefix(ref, "msgid=") {
		msgid := ref[6:]
		for i, m := range messages {
			if m.MsgID == msgid {
				return i
			}
		}
		return -1
	}

	if strings.HasPrefix(ref, "timestamp=") {
		tsStr := ref[10:]
		ts, err := time.Parse(time.RFC3339, tsStr)
		if err != nil {
			return -1
		}
		// Find first message at or after timestamp
		for i, m := range messages {
			if !m.Time.Before(ts) {
				return i
			}
		}
		return len(messages) // Past end
	}

	return -1
}

// sendBatch sends a batch of history messages
func (h *ChatHistoryHandler) sendBatch(c *Client, target string, messages []StoredMessage, label string) {
	batchID := fmt.Sprintf("hist%d", time.Now().UnixNano())

	// Start batch
	startTags := make(map[string]string)
	if label != "" {
		startTags["label"] = label
	}
	h.ircv3.SendWithTags(c, startTags, fmt.Sprintf(":%s BATCH +%s chathistory %s", h.server.name, batchID, target))

	// Send messages
	for _, msg := range messages {
		tags := map[string]string{
			"batch": batchID,
			"msgid": msg.MsgID,
			"time":  msg.Time.Format("2006-01-02T15:04:05.000Z"),
		}
		if msg.Account != "" && c.caps["account-tag"] {
			tags["account"] = msg.Account
		}
		if msg.DID != "" && c.caps["identity"] {
			tags["did"] = msg.DID
		}

		line := fmt.Sprintf(":%s %s %s :%s", msg.Prefix, msg.Command, msg.Target, msg.Text)
		h.ircv3.SendWithTags(c, tags, line)
	}

	// End batch
	c.Send(fmt.Sprintf(":%s BATCH -%s", h.server.name, batchID))
}

// sendEmptyBatch sends an empty batch (no messages found)
func (h *ChatHistoryHandler) sendEmptyBatch(c *Client, target string, label string) {
	batchID := fmt.Sprintf("hist%d", time.Now().UnixNano())

	startTags := make(map[string]string)
	if label != "" {
		startTags["label"] = label
	}
	h.ircv3.SendWithTags(c, startTags, fmt.Sprintf(":%s BATCH +%s chathistory %s", h.server.name, batchID, target))
	c.Send(fmt.Sprintf(":%s BATCH -%s", h.server.name, batchID))
}

// parseLimit parses a limit parameter with bounds checking
func parseLimit(s string) int {
	limit, err := strconv.Atoi(s)
	if err != nil || limit <= 0 {
		return DefaultHistoryLimit
	}
	if limit > MaxHistoryRequestSize {
		return MaxHistoryRequestSize
	}
	return limit
}
