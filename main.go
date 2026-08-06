package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// MeshIRCd: federated IRC server with JSON-LD S2S, DID identity, and GitHub-based discovery

const (
	serverName      = "meshircd"
	serverVersion   = "0.1.0"
	maxNickLen      = 30
	maxChannelLen   = 50
	maxLineLen      = 512
	maxTargets      = 4
	maxIdentitySize = 16384 // 16KB limit for identity JSON documents
)

// Numeric replies
const (
	RPL_WELCOME             = "001"
	RPL_YOURHOST            = "002"
	RPL_CREATED             = "003"
	RPL_MYINFO              = "004"
	RPL_ISUPPORT            = "005"
	RPL_UMODEIS             = "221"
	RPL_WHOISIDENTITY       = "320" // Used for identity in WHOIS
	RPL_LUSERCLIENT      = "251"
	RPL_LUSEROP          = "252"
	RPL_LUSERUNKNOWN     = "253"
	RPL_LUSERCHANNELS    = "254"
	RPL_LUSERME          = "255"
	RPL_AWAY             = "301"
	RPL_USERHOST         = "302"
	RPL_ISON             = "303"
	RPL_UNAWAY           = "305"
	RPL_NOWAWAY          = "306"
	RPL_WHOISUSER        = "311"
	RPL_WHOISSERVER      = "312"
	RPL_WHOISOPERATOR    = "313"
	RPL_ENDOFWHO         = "315"
	RPL_WHOISIDLE        = "317"
	RPL_ENDOFWHOIS       = "318"
	RPL_WHOISCHANNELS    = "319"
	RPL_LIST             = "322"
	RPL_LISTEND          = "323"
	RPL_CHANNELMODEIS    = "324"
	RPL_CREATIONTIME     = "329"
	RPL_NOTOPIC          = "331"
	RPL_TOPIC            = "332"
	RPL_TOPICWHOTIME     = "333"
	RPL_INVITING         = "341"
	RPL_INVITELIST       = "346"
	RPL_ENDOFINVITELIST  = "347"
	RPL_EXCEPTLIST       = "348"
	RPL_ENDOFEXCEPTLIST  = "349"
	RPL_VERSION          = "351"
	RPL_WHOREPLY         = "352"
	RPL_NAMREPLY         = "353"
	RPL_ENDOFNAMES       = "366"
	RPL_BANLIST          = "367"
	RPL_ENDOFBANLIST     = "368"
	RPL_MOTD             = "372"
	RPL_MOTDSTART        = "375"
	RPL_ENDOFMOTD        = "376"
	RPL_YOUREOPER        = "381"
	RPL_TIME             = "391"
	ERR_NOSUCHNICK       = "401"
	ERR_NOSUCHSERVER     = "402"
	ERR_NOSUCHCHANNEL    = "403"
	ERR_CANNOTSENDTOCHAN = "404"
	ERR_TOOMANYTARGETS   = "407"
	ERR_NORECIPIENT      = "411"
	ERR_NOTEXTTOSEND     = "412"
	ERR_UNKNOWNCOMMAND   = "421"
	ERR_NOMOTD           = "422"
	ERR_NONICKNAMEGIVEN  = "431"
	ERR_ERRONEUSNICKNAME = "432"
	ERR_NICKNAMEINUSE    = "433"
	ERR_USERNOTINCHANNEL = "441"
	ERR_NOTONCHANNEL     = "442"
	ERR_USERONCHANNEL    = "443"
	ERR_NOTREGISTERED    = "451"
	ERR_NEEDMOREPARAMS   = "461"
	ERR_ALREADYREGISTRED = "462"
	ERR_PASSWDMISMATCH   = "464"
	ERR_CHANNELISFULL    = "471"
	ERR_UNKNOWNMODE      = "472"
	ERR_INVITEONLYCHAN   = "473"
	ERR_BANNEDFROMCHAN   = "474"
	ERR_BADCHANNELKEY    = "475"
	ERR_BADCHANMASK      = "476"
	ERR_CHANOPRIVSNEEDED = "482"
	ERR_NOPRIVILEGES     = "481"
	ERR_UMODEUNKNOWNFLAG = "501"
	ERR_USERSDONTMATCH   = "502"
	// WATCH numerics
	RPL_LOGON          = "600"
	RPL_LOGOFF         = "601"
	RPL_WATCHOFF       = "602"
	RPL_WATCHSTAT      = "603"
	RPL_NOWON          = "604"
	RPL_NOWOFF         = "605"
	RPL_WATCHLIST      = "606"
	RPL_ENDOFWATCHLIST = "607"
	// MONITOR numerics
	RPL_MONONLINE      = "730"
	RPL_MONOFFLINE     = "731"
	RPL_MONLIST        = "732"
	RPL_ENDOFMONLIST   = "733"
	ERR_MONLISTFULL    = "734"
	RPL_METADATAEND    = "762"
)

// Message represents a parsed IRC message
type Message struct {
	Prefix  string
	Command string
	Params  []string
}

func (m *Message) Trailing() string {
	if len(m.Params) > 0 {
		return m.Params[len(m.Params)-1]
	}
	return ""
}

func parseMessage(line string) *Message {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil
	}

	msg := &Message{}
	if line[0] == ':' {
		idx := strings.Index(line, " ")
		if idx == -1 {
			return nil
		}
		msg.Prefix = line[1:idx]
		line = line[idx+1:]
	}

	if idx := strings.Index(line, " :"); idx != -1 {
		trailing := line[idx+2:]
		line = line[:idx]
		msg.Params = strings.Fields(line)
		msg.Params = append(msg.Params, trailing)
	} else {
		msg.Params = strings.Fields(line)
	}

	if len(msg.Params) == 0 {
		return nil
	}
	msg.Command = strings.ToUpper(msg.Params[0])
	msg.Params = msg.Params[1:]
	return msg
}

// Client represents a connected IRC client
type Client struct {
	conn       net.Conn
	server     *Server
	send       chan string
	nick       string
	user       string
	realname   string
	hostname   string
	registered bool
	away       string
	modes      map[rune]bool
	channels   map[string]*Channel // protected by c.mu
	signon     time.Time
	lastActive time.Time
	mu         sync.RWMutex // protects nick, away, modes, lastActive, account, did, identity, channels
	quit       bool
	capNeg     bool
	caps       map[string]bool
	pass       string // stored during registration
	account    string // logged-in account name
	did               string      // DID (did:key or did:web) if authenticated
	identity          string      // Full JSON-LD identity document (set via METADATA)
	identityVerified  bool        // true only if this server verified the identity proof
	sasl              SASLSession // SASL authentication state
	lastChallengeTime time.Time   // rate limiting for IDENTITY CHALLENGE
	monitor           map[string]bool // MONITOR list (lowercase nicks)
	watch             map[string]bool // WATCH list (lowercase nicks)
	floodTokens       float64         // ponytail: token bucket, 5 msg/sec burst 10
	floodLastTime     time.Time
}

func newClient(conn net.Conn, server *Server) *Client {
	// Cloak all users with server name - no IP exposure
	return &Client{
		conn:       conn,
		server:     server,
		send:       make(chan string, 256),
		hostname:   server.name,
		modes:      make(map[rune]bool),
		channels:   make(map[string]*Channel),
		signon:     time.Now(),
		lastActive: time.Now(),
		caps:       make(map[string]bool),
		monitor:       make(map[string]bool),
		watch:         make(map[string]bool),
		floodTokens:   10, // start with full bucket
		floodLastTime: time.Now(),
	}
}

func (c *Client) Prefix() string {
	c.mu.RLock()
	nick := c.nick
	c.mu.RUnlock()
	return fmt.Sprintf("%s!%s@%s", nick, c.user, c.hostname)
}

func (c *Client) Nick() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nick
}

func (c *Client) Away() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.away
}

func (c *Client) Account() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.account
}

func (c *Client) DID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.did
}

func (c *Client) Send(line string) {
	c.mu.RLock()
	quit := c.quit
	c.mu.RUnlock()
	if quit {
		return
	}
	defer func() {
		recover() // ignore send on closed channel (race between quit check and close)
	}()
	select {
	case c.send <- line:
	default:
		// buffer full, drop — could log this
	}
}

func (c *Client) SendNumeric(numeric, params string) {
	c.mu.RLock()
	nick := c.nick
	c.mu.RUnlock()
	if nick == "" {
		nick = "*"
	}
	c.Send(fmt.Sprintf(":%s %s %s %s", c.server.name, numeric, nick, params))
}

func (c *Client) SendFrom(prefix, cmd string, params ...string) {
	var line string
	if len(params) > 0 {
		last := params[len(params)-1]
		if strings.Contains(last, " ") || strings.HasPrefix(last, ":") || last == "" {
			params[len(params)-1] = ":" + last
		}
		line = fmt.Sprintf(":%s %s %s", prefix, cmd, strings.Join(params, " "))
	} else {
		line = fmt.Sprintf(":%s %s", prefix, cmd)
	}
	c.Send(line)
}

func (c *Client) readLoop() {
	defer c.server.removeClient(c)
	scanner := bufio.NewScanner(c.conn)
	scanner.Buffer(make([]byte, maxLineLen), maxLineLen)

	for scanner.Scan() {
		line := scanner.Text()
		if parsed := ParseMessageWithTags(line); parsed != nil {
			// ponytail: token bucket flood control, 5 msg/sec burst 10
			now := time.Now()
			c.floodTokens += now.Sub(c.floodLastTime).Seconds() * 5.0
			if c.floodTokens > 10 {
				c.floodTokens = 10
			}
			c.floodLastTime = now
			if c.floodTokens < 1 {
				continue // drop message
			}
			c.floodTokens--

			c.mu.Lock()
			c.lastActive = time.Now()
			c.mu.Unlock()
			c.server.handleMessageWithTags(c, parsed)
		}
	}
}

func (c *Client) writeLoop() {
	for line := range c.send {
		_ = c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, err := fmt.Fprintf(c.conn, "%s\r\n", line)
		if err != nil {
			return
		}
	}
}

// Channel events for the actor model
type chanEvent interface {
	handle(ch *Channel)
}

type evJoin struct {
	client *Client
	key    string
}

type evPart struct {
	client *Client
	reason string
}

type evQuit struct {
	client *Client
	reason string
}

type evMessage struct {
	client   *Client
	text     string
	isNotice bool
	msgID    string // IRCv3 message ID
	time     string // IRCv3 server-time
	account  string // sender account
	did      string // sender DID
}

type evMode struct {
	client  *Client
	modeStr string
	params  []string
}

type evTopic struct {
	client   *Client
	newTopic *string // nil = query
}

type evKick struct {
	client *Client
	target *Client
	reason string
}

type evInvite struct {
	client *Client
	target *Client
}

type evNames struct {
	client *Client
}

type evWho struct {
	client *Client
}

type evNickChange struct {
	client  *Client
	oldNick string
	newNick string
}

type evShutdown struct{}

type evListInfo struct {
	reply chan int
}

type evMemberModes struct {
	target *Client
	reply  chan string // modes or "" if not a member
}

type evAwayNotify struct {
	client  *Client
	awayMsg string // empty string means user is no longer away
}

// Channel represents an IRC channel with its own goroutine
type Channel struct {
	name      string
	topic     string
	topicWho  string
	topicTime time.Time
	created   time.Time
	modes     map[rune]bool
	key       string
	limit     int
	members       map[*Client]string      // client -> modes (o, v)
	remoteMembers map[string]*RemoteUser  // URN -> remote user
	bans          map[string]banEntry
	invites   map[string]bool // invited nicks (lowercase)
	events    chan chanEvent
	done      chan struct{} // closed when run() exits
	server    *Server
}

type banEntry struct {
	mask string
	who  string
	when time.Time
}

func newChannel(name string, server *Server) *Channel {
	ch := &Channel{
		name:    name,
		created: time.Now(),
		modes:         map[rune]bool{'n': true, 't': true},
		members:       make(map[*Client]string),
		remoteMembers: make(map[string]*RemoteUser),
		bans:          make(map[string]banEntry),
		invites: make(map[string]bool),
		events:  make(chan chanEvent, 256),
		done:    make(chan struct{}),
		server:  server,
	}
	go ch.run()
	return ch
}

func (ch *Channel) run() {
	defer close(ch.done)
	for ev := range ch.events {
		ev.handle(ch)
		if _, ok := ev.(evShutdown); ok {
			return
		}
	}
}

// trySendChanEvent attempts a non-blocking send to the channel's event queue.
// Returns true if the event was sent, false if the queue was full (event dropped).
func (ch *Channel) trySendChanEvent(ev chanEvent) bool {
	select {
	case ch.events <- ev:
		return true
	default:
		log.Printf("warning: dropped %T event for channel %s (queue full)", ev, ch.name)
		return false
	}
}

// sendChanEventWithTimeout sends an event and waits for up to timeout.
// Returns true if sent, false if timed out.
func (ch *Channel) sendChanEventWithTimeout(ev chanEvent, timeout time.Duration) bool {
	select {
	case ch.events <- ev:
		return true
	case <-time.After(timeout):
		log.Printf("warning: timed out sending %T event for channel %s", ev, ch.name)
		return false
	}
}

func (ch *Channel) broadcast(line string, exclude *Client) {
	for c := range ch.members {
		if c != exclude {
			c.Send(line)
		}
	}
}

func (ch *Channel) isMember(c *Client) bool {
	_, ok := ch.members[c]
	return ok
}

func (ch *Channel) isOp(c *Client) bool {
	return strings.Contains(ch.members[c], "o")
}

func (ch *Channel) isVoice(c *Client) bool {
	m := ch.members[c]
	return strings.Contains(m, "o") || strings.Contains(m, "v")
}

func (ch *Channel) memberCount() int {
	return len(ch.members)
}

// Event handlers - all run in channel's goroutine, no locks needed

func (ev evJoin) handle(ch *Channel) {
	c := ev.client

	if ch.isMember(c) {
		return
	}

	// check invite-only
	if ch.modes['i'] && !ch.invites[strings.ToLower(c.Nick())] {
		c.SendNumeric(ERR_INVITEONLYCHAN, fmt.Sprintf("%s :Cannot join channel (+i)", ch.name))
		return
	}

	// check key
	if ch.key != "" && ch.key != ev.key {
		c.SendNumeric(ERR_BADCHANNELKEY, fmt.Sprintf("%s :Cannot join channel (+k)", ch.name))
		return
	}

	// check limit
	if ch.limit > 0 && len(ch.members) >= ch.limit {
		c.SendNumeric(ERR_CHANNELISFULL, fmt.Sprintf("%s :Cannot join channel (+l)", ch.name))
		return
	}

	// check bans
	prefix := c.Prefix()
	for _, ban := range ch.bans {
		if matchMask(prefix, ban.mask) {
			c.SendNumeric(ERR_BANNEDFROMCHAN, fmt.Sprintf("%s :Cannot join channel (+b)", ch.name))
			return
		}
	}

	// first user gets op
	if len(ch.members) == 0 {
		ch.members[c] = "o"
	} else {
		ch.members[c] = ""
	}
	delete(ch.invites, strings.ToLower(c.Nick()))

	// update client's channel list
	c.mu.Lock()
	c.channels[strings.ToLower(ch.name)] = ch
	c.mu.Unlock()

	// broadcast join with appropriate format per-client
	c.mu.RLock()
	account := c.account
	did := c.did
	c.mu.RUnlock()
	if account == "" {
		account = "*"
	}

	for member := range ch.members {
		var joinMsg string
		if member.caps["extended-join"] {
			// extended-join: JOIN #channel account :realname
			joinMsg = fmt.Sprintf(":%s JOIN %s %s :%s", c.Prefix(), ch.name, account, c.realname)
		} else {
			joinMsg = fmt.Sprintf(":%s JOIN %s", c.Prefix(), ch.name)
		}
		// Add DID tag for clients with identity cap
		if member.caps["identity"] && did != "" {
			joinMsg = fmt.Sprintf("@did=%s %s", escapeTagValue(did), joinMsg)
		}
		member.Send(joinMsg)
	}

	// send topic
	if ch.topic != "" {
		c.SendNumeric(RPL_TOPIC, fmt.Sprintf("%s :%s", ch.name, ch.topic))
		c.SendNumeric(RPL_TOPICWHOTIME, fmt.Sprintf("%s %s %d", ch.name, ch.topicWho, ch.topicTime.Unix()))
	}

	// send names
	ev2 := evNames{client: c}
	ev2.handle(ch)

	// Broadcast Join to federation
	if ch.server.federation != nil {
		modes := ch.members[c]
		ch.server.federation.BroadcastJoin(c, ch.name, modes)
	}
}

func (ev evPart) handle(ch *Channel) {
	c := ev.client

	if !ch.isMember(c) {
		c.SendNumeric(ERR_NOTONCHANNEL, fmt.Sprintf("%s :You're not on that channel", ch.name))
		return
	}

	partMsg := fmt.Sprintf(":%s PART %s", c.Prefix(), ch.name)
	if ev.reason != "" {
		partMsg += " :" + ev.reason
	}
	ch.broadcast(partMsg, nil)

	delete(ch.members, c)

	c.mu.Lock()
	delete(c.channels, strings.ToLower(ch.name))
	c.mu.Unlock()

	// Broadcast Part to federation
	if ch.server.federation != nil {
		ch.server.federation.BroadcastPart(c, ch.name, ev.reason)
	}

	if len(ch.members) == 0 {
		ch.server.removeChannel(ch)
	}
}

func (ev evQuit) handle(ch *Channel) {
	c := ev.client

	if !ch.isMember(c) {
		return
	}

	quitMsg := fmt.Sprintf(":%s QUIT :%s", c.Prefix(), ev.reason)
	ch.broadcast(quitMsg, c)

	delete(ch.members, c)

	if len(ch.members) == 0 {
		ch.server.removeChannel(ch)
	}
}

func (ev evMessage) handle(ch *Channel) {
	c := ev.client
	cmd := "PRIVMSG"
	if ev.isNotice {
		cmd = "NOTICE"
	}

	// check if can send
	if ch.modes['n'] && !ch.isMember(c) {
		if !ev.isNotice {
			c.SendNumeric(ERR_CANNOTSENDTOCHAN, fmt.Sprintf("%s :Cannot send to channel", ch.name))
		}
		return
	}
	if ch.modes['m'] && !ch.isVoice(c) {
		if !ev.isNotice {
			c.SendNumeric(ERR_CANNOTSENDTOCHAN, fmt.Sprintf("%s :Cannot send to channel (+m)", ch.name))
		}
		return
	}

	// Broadcast with IRCv3 tags to each member
	baseLine := fmt.Sprintf(":%s %s %s :%s", c.Prefix(), cmd, ch.name, ev.text)
	for member := range ch.members {
		if member == c {
			continue // sender handled separately via echo-message
		}
		tags := ch.server.buildMsgTags(member, ev.msgID, ev.time, ev.account, ev.did)
		ch.server.ircv3.SendWithTags(member, tags, baseLine)
	}

	// Broadcast to federation
	if ch.server.federation != nil {
		if ev.isNotice {
			ch.server.federation.BroadcastNotice(c, MakeChannelURN(ch.name), "", ev.text)
		} else {
			ch.server.federation.BroadcastChannelMessage(c, ch.name, ev.text)
		}
	}
}

func (ev evMode) handle(ch *Channel) {
	c := ev.client

	// Treat empty mode string or just +/- (no actual mode letters) as a query
	// Also treat list modes (b, e, I) without params as queries
	isQuery := true
	for _, m := range ev.modeStr {
		if m != '+' && m != '-' {
			isQuery = false
			break
		}
	}
	// Check for list mode queries: "b", "e", "I" with no parameters
	isListQuery := false
	if len(ev.params) == 0 {
		listOnly := true
		for _, m := range ev.modeStr {
			if m != 'b' && m != 'e' && m != 'I' && m != '+' && m != '-' {
				listOnly = false
				break
			}
		}
		if listOnly && ev.modeStr != "" {
			isListQuery = true
		}
	}
	if isQuery {
		// query
		var modes string
		var args []string
		for m := range ch.modes {
			modes += string(m)
		}
		if ch.key != "" {
			modes += "k"
			if ch.isMember(c) {
				args = append(args, ch.key)
			}
		}
		if ch.limit > 0 {
			modes += "l"
			args = append(args, fmt.Sprintf("%d", ch.limit))
		}
		if modes == "" {
			modes = "+"
		} else {
			modes = "+" + modes
		}
		c.SendNumeric(RPL_CHANNELMODEIS, fmt.Sprintf("%s %s %s", ch.name, modes, strings.Join(args, " ")))
		c.SendNumeric(RPL_CREATIONTIME, fmt.Sprintf("%s %d", ch.name, ch.created.Unix()))
		return
	}

	// Handle list mode queries (b, e, I without params) - anyone can query these
	if isListQuery {
		for _, m := range ev.modeStr {
			switch m {
			case 'b':
				for _, ban := range ch.bans {
					c.SendNumeric(RPL_BANLIST, fmt.Sprintf("%s %s", ch.name, ban.mask))
				}
				c.SendNumeric(RPL_ENDOFBANLIST, fmt.Sprintf("%s :End of channel ban list", ch.name))
			case 'e':
				// Exception list not implemented yet, just send end
				c.SendNumeric(RPL_ENDOFEXCEPTLIST, fmt.Sprintf("%s :End of channel exception list", ch.name))
			case 'I':
				// Invite exception list not implemented yet, just send end
				c.SendNumeric(RPL_ENDOFINVITELIST, fmt.Sprintf("%s :End of channel invite list", ch.name))
			}
		}
		return
	}

	if !ch.isOp(c) {
		c.SendNumeric(ERR_CHANOPRIVSNEEDED, fmt.Sprintf("%s :You're not channel operator", ch.name))
		return
	}

	params := ev.params
	paramIdx := 0
	add := true
	var changes []string
	var changeParams []string

	for _, m := range ev.modeStr {
		switch m {
		case '+':
			add = true
		case '-':
			add = false
		case 'o', 'v':
			if paramIdx >= len(params) {
				continue
			}
			target := ch.server.getClient(params[paramIdx])
			paramIdx++
			if target == nil || !ch.isMember(target) {
				if target != nil {
					c.SendNumeric(ERR_USERNOTINCHANNEL, fmt.Sprintf("%s %s :They aren't on that channel", target.Nick(), ch.name))
				}
				continue
			}
			modes := ch.members[target]
			if add {
				if !strings.ContainsRune(modes, m) {
					ch.members[target] = modes + string(m)
					changes = append(changes, "+"+string(m))
					changeParams = append(changeParams, target.Nick())
				}
			} else {
				if strings.ContainsRune(modes, m) {
					ch.members[target] = strings.Replace(modes, string(m), "", 1)
					changes = append(changes, "-"+string(m))
					changeParams = append(changeParams, target.Nick())
				}
			}
		case 'b':
			if paramIdx >= len(params) {
				// list bans
				for _, ban := range ch.bans {
					c.SendNumeric(RPL_BANLIST, fmt.Sprintf("%s %s %s %d", ch.name, ban.mask, ban.who, ban.when.Unix()))
				}
				c.SendNumeric(RPL_ENDOFBANLIST, fmt.Sprintf("%s :End of channel ban list", ch.name))
				continue
			}
			mask := params[paramIdx]
			paramIdx++
			if add {
				ch.bans[strings.ToLower(mask)] = banEntry{mask: mask, who: c.Prefix(), when: time.Now()}
				changes = append(changes, "+b")
				changeParams = append(changeParams, mask)
			} else {
				delete(ch.bans, strings.ToLower(mask))
				changes = append(changes, "-b")
				changeParams = append(changeParams, mask)
			}
		case 'k':
			if add {
				if paramIdx >= len(params) {
					continue
				}
				ch.key = params[paramIdx]
				paramIdx++
				changes = append(changes, "+k")
				changeParams = append(changeParams, ch.key)
			} else {
				ch.key = ""
				changes = append(changes, "-k")
				changeParams = append(changeParams, "*")
			}
		case 'l':
			if add {
				if paramIdx >= len(params) {
					continue
				}
				var limit int
				fmt.Sscanf(params[paramIdx], "%d", &limit)
				paramIdx++
				if limit > 0 {
					ch.limit = limit
					changes = append(changes, "+l")
					changeParams = append(changeParams, fmt.Sprintf("%d", limit))
				}
			} else {
				ch.limit = 0
				changes = append(changes, "-l")
			}
		case 'i', 'm', 'n', 'p', 's', 't':
			if add {
				if !ch.modes[m] {
					ch.modes[m] = true
					changes = append(changes, "+"+string(m))
				}
			} else {
				if ch.modes[m] {
					delete(ch.modes, m)
					changes = append(changes, "-"+string(m))
				}
			}
		default:
			c.SendNumeric(ERR_UNKNOWNMODE, fmt.Sprintf("%c :is unknown mode char to me", m))
		}
	}

	if len(changes) > 0 {
		var modeChange string
		currentDir := ""
		for _, change := range changes {
			dir := string(change[0])
			mode := change[1:]
			if dir != currentDir {
				modeChange += dir
				currentDir = dir
			}
			modeChange += mode
		}
		allParams := append([]string{ch.name, modeChange}, changeParams...)
		line := fmt.Sprintf(":%s MODE %s", c.Prefix(), strings.Join(allParams, " "))
		ch.broadcast(line, nil)

		// Broadcast Mode to federation
		if ch.server.federation != nil {
			modeWithParams := modeChange
			if len(changeParams) > 0 {
				modeWithParams += " " + strings.Join(changeParams, " ")
			}
			ch.server.federation.BroadcastMode(c, ch.name, modeWithParams)
		}
	}
}

func (ev evTopic) handle(ch *Channel) {
	c := ev.client

	if ev.newTopic == nil {
		// query
		if ch.topic == "" {
			c.SendNumeric(RPL_NOTOPIC, fmt.Sprintf("%s :No topic is set", ch.name))
		} else {
			c.SendNumeric(RPL_TOPIC, fmt.Sprintf("%s :%s", ch.name, ch.topic))
			c.SendNumeric(RPL_TOPICWHOTIME, fmt.Sprintf("%s %s %d", ch.name, ch.topicWho, ch.topicTime.Unix()))
		}
		return
	}

	if !ch.isMember(c) {
		c.SendNumeric(ERR_NOTONCHANNEL, fmt.Sprintf("%s :You're not on that channel", ch.name))
		return
	}

	if ch.modes['t'] && !ch.isOp(c) {
		c.SendNumeric(ERR_CHANOPRIVSNEEDED, fmt.Sprintf("%s :You're not channel operator", ch.name))
		return
	}

	ch.topic = *ev.newTopic
	ch.topicWho = c.Prefix()
	ch.topicTime = time.Now()

	ch.broadcast(fmt.Sprintf(":%s TOPIC %s :%s", c.Prefix(), ch.name, ch.topic), nil)

	// Broadcast Topic to federation
	if ch.server.federation != nil {
		ch.server.federation.BroadcastTopic(c, ch.name, ch.topic)
	}
}

func (ev evKick) handle(ch *Channel) {
	c := ev.client

	if !ch.isOp(c) {
		c.SendNumeric(ERR_CHANOPRIVSNEEDED, fmt.Sprintf("%s :You're not channel operator", ch.name))
		return
	}

	if !ch.isMember(ev.target) {
		c.SendNumeric(ERR_USERNOTINCHANNEL, fmt.Sprintf("%s %s :They aren't on that channel", ev.target.Nick(), ch.name))
		return
	}

	ch.broadcast(fmt.Sprintf(":%s KICK %s %s :%s", c.Prefix(), ch.name, ev.target.Nick(), ev.reason), nil)

	delete(ch.members, ev.target)

	ch.server.mu.Lock()
	delete(ev.target.channels, strings.ToLower(ch.name))
	ch.server.mu.Unlock()

	// Broadcast Kick to federation
	if ch.server.federation != nil {
		ch.server.federation.BroadcastKick(c, ev.target, ch.name, ev.reason)
	}

	if len(ch.members) == 0 {
		ch.server.removeChannel(ch)
	}
}

func (ev evInvite) handle(ch *Channel) {
	c := ev.client

	if !ch.isMember(c) {
		c.SendNumeric(ERR_NOTONCHANNEL, fmt.Sprintf("%s :You're not on that channel", ch.name))
		return
	}

	if ch.modes['i'] && !ch.isOp(c) {
		c.SendNumeric(ERR_CHANOPRIVSNEEDED, fmt.Sprintf("%s :You're not channel operator", ch.name))
		return
	}

	if ch.isMember(ev.target) {
		c.SendNumeric(ERR_USERONCHANNEL, fmt.Sprintf("%s %s :is already on channel", ev.target.Nick(), ch.name))
		return
	}

	ch.invites[strings.ToLower(ev.target.Nick())] = true

	c.SendNumeric(RPL_INVITING, fmt.Sprintf("%s %s", ev.target.Nick(), ch.name))
	ev.target.SendFrom(c.Prefix(), "INVITE", ev.target.Nick(), ch.name)

	if away := ev.target.Away(); away != "" {
		c.SendNumeric(RPL_AWAY, fmt.Sprintf("%s :%s", ev.target.Nick(), away))
	}
}

func (ev evNames) handle(ch *Channel) {
	c := ev.client

	var names []string
	for member, modes := range ch.members {
		prefix := ""
		if strings.Contains(modes, "o") {
			prefix = "@"
		} else if strings.Contains(modes, "v") {
			prefix = "+"
		}
		names = append(names, prefix+member.Nick())
	}

	sort.Strings(names)
	c.SendNumeric(RPL_NAMREPLY, fmt.Sprintf("= %s :%s", ch.name, strings.Join(names, " ")))
	c.SendNumeric(RPL_ENDOFNAMES, fmt.Sprintf("%s :End of NAMES list", ch.name))
}

func (ev evWho) handle(ch *Channel) {
	c := ev.client

	for member, modes := range ch.members {
		flags := "H"
		if member.Away() != "" {
			flags = "G"
		}
		if strings.Contains(modes, "o") {
			flags += "@"
		} else if strings.Contains(modes, "v") {
			flags += "+"
		}
		c.SendNumeric(RPL_WHOREPLY, fmt.Sprintf("%s %s %s %s %s %s :0 %s",
			ch.name, member.user, member.hostname, ch.server.name, member.Nick(), flags, member.realname))
	}
	c.SendNumeric(RPL_ENDOFWHO, fmt.Sprintf("%s :End of WHO list", ch.name))
}

func (ev evNickChange) handle(ch *Channel) {
	// update invite list if old nick was invited
	oldLower := strings.ToLower(ev.oldNick)
	newLower := strings.ToLower(ev.newNick)
	if ch.invites[oldLower] {
		delete(ch.invites, oldLower)
		ch.invites[newLower] = true
	}

	// broadcast nick change to channel members
	msg := fmt.Sprintf(":%s!%s@%s NICK %s", ev.oldNick, ev.client.user, ev.client.hostname, ev.newNick)
	ch.broadcast(msg, ev.client)
}

func (ev evListInfo) handle(ch *Channel) {
	ev.reply <- len(ch.members)
}

func (ev evMemberModes) handle(ch *Channel) {
	ev.reply <- ch.members[ev.target] // "" if not present
}

func (ev evAwayNotify) handle(ch *Channel) {
	awayMsg := fmt.Sprintf(":%s AWAY :%s", ev.client.Prefix(), ev.awayMsg)
	for member := range ch.members {
		if member != ev.client && member.caps["away-notify"] {
			member.Send(awayMsg)
		}
	}
}

func (ev evShutdown) handle(ch *Channel) {
	// channel is being destroyed, nothing to do
}

// PendingChallenge stores an identity challenge awaiting proof
type PendingChallenge struct {
	Challenge string
	Expires   time.Time
}

// ChallengeStore manages pending identity challenges
type ChallengeStore struct {
	mu         sync.RWMutex
	challenges map[*Client]*PendingChallenge
}

func newChallengeStore() *ChallengeStore {
	return &ChallengeStore{
		challenges: make(map[*Client]*PendingChallenge),
	}
}

func (cs *ChallengeStore) Set(c *Client, challenge string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	// Sweep expired entries if map is large to prevent unbounded growth
	if len(cs.challenges) > 100 {
		now := time.Now()
		for k, v := range cs.challenges {
			if now.After(v.Expires) {
				delete(cs.challenges, k)
			}
		}
	}
	cs.challenges[c] = &PendingChallenge{
		Challenge: challenge,
		Expires:   time.Now().Add(5 * time.Minute),
	}
}

func (cs *ChallengeStore) Get(c *Client) string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if pc, ok := cs.challenges[c]; ok {
		if time.Now().Before(pc.Expires) {
			return pc.Challenge
		}
		// Clean up expired entry
		delete(cs.challenges, c)
	}
	return ""
}

func (cs *ChallengeStore) Clear(c *Client) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.challenges, c)
}

// Server holds all state
type Server struct {
	name        string
	network     string
	created     time.Time
	motd        []string
	clients     map[string]*Client  // lowercase nick -> client
	channels    map[string]*Channel // lowercase name -> channel
	password    string
	operPass    string
	mu          sync.RWMutex
	caps        map[string]bool
	ircv3       *IRCv3Handler
	history     *ChatHistoryStore
	chathistory *ChatHistoryHandler
	federation  *FederationManager
	challenges  *ChallengeStore // pending identity challenges
}

func newServer(name, network, password, operPass string) *Server {
	s := &Server{
		name:     name,
		network:  network,
		created:  time.Now(),
		clients:  make(map[string]*Client),
		channels: make(map[string]*Channel),
		password: password,
		operPass: operPass,
		caps: map[string]bool{
			"multi-prefix":      true,
			"away-notify":       true,
			"account-notify":    true,
			"account-tag":       true,
			"extended-join":     true,
			"server-time":       true,
			"message-tags":      true,
			"message-ids":       true,
			"batch":             true,
			"cap-notify":        true,
			"echo-message":      true,
			"labeled-response":  true,
			"sasl":              true, // value will be shown as EXTERNAL,PLAIN in CAP LS
			"draft/chathistory": true,
			"chghost":           true,
			"setname":           true,
			"invite-notify":     true,
			"identity":          true,
			"metadata":          true,
		},
		history:    newChatHistoryStore(),
		challenges: newChallengeStore(),
	}
	s.ircv3 = newIRCv3Handler(s)
	s.chathistory = newChatHistoryHandler(s, s.history, s.ircv3)
	return s
}

func (s *Server) getClient(nick string) *Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[strings.ToLower(nick)]
}

func (s *Server) getChannel(name string) *Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.channels[strings.ToLower(name)]
}

func (s *Server) getOrCreateChannel(name string) *Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(name)
	if ch, ok := s.channels[key]; ok {
		return ch
	}
	ch := newChannel(name, s)
	s.channels[key] = ch
	return ch
}

func (s *Server) removeChannel(ch *Channel) {
	s.mu.Lock()
	delete(s.channels, strings.ToLower(ch.name))
	s.mu.Unlock()

	// Send shutdown event (blocking) and wait for goroutine acknowledgment
	ch.events <- evShutdown{}
	<-ch.done
	close(ch.events)
}

func (s *Server) removeClient(c *Client) {
	c.mu.Lock()
	if c.quit {
		c.mu.Unlock()
		return
	}
	c.quit = true
	nick := c.nick
	c.mu.Unlock()

	// Broadcast UserOffline to federation before removing from server state
	if s.federation != nil && nick != "" {
		s.federation.BroadcastUserOffline(c, "Connection closed")
	}

	// Notify MONITOR/WATCH watchers before removing
	if nick != "" {
		s.notifyWatchers(c, false)
	}

	s.mu.Lock()
	delete(s.clients, strings.ToLower(nick))
	s.mu.Unlock()

	c.mu.Lock()
	chans := make([]*Channel, 0, len(c.channels))
	for _, ch := range c.channels {
		chans = append(chans, ch)
	}
	c.channels = make(map[string]*Channel)
	c.mu.Unlock()

	// notify all channels
	for _, ch := range chans {
		select {
		case ch.events <- evQuit{client: c, reason: "Connection closed"}:
		default:
		}
	}

	close(c.send)
	c.conn.Close()
}

func (s *Server) handleMessageWithTags(c *Client, parsed *ParsedIRCMessage) {
	// Extract label for labeled-response
	label := s.ircv3.HandleLabeledRequest(c, parsed.Tags)

	// Handle the message
	s.handleMessage(c, parsed.Message)

	// Clear label after handling
	if label != "" {
		s.ircv3.labelTracker.ClearLabel(c)
	}
}

func (s *Server) handleMessage(c *Client, msg *Message) {
	switch msg.Command {
	case "CAP":
		s.handleCAP(c, msg)
		return
	case "PASS":
		s.handlePASS(c, msg)
		return
	case "NICK":
		s.handleNICK(c, msg)
		return
	case "USER":
		s.handleUSER(c, msg)
		return
	case "AUTHENTICATE":
		s.ircv3.HandleAUTHENTICATE(c, msg)
		return
	case "QUIT":
		s.handleQUIT(c, msg)
		return
	case "PING":
		s.handlePING(c, msg)
		return
	case "PONG":
		return
	}

	if !c.registered {
		c.SendNumeric(ERR_NOTREGISTERED, ":You have not registered")
		return
	}

	switch msg.Command {
	case "JOIN":
		s.handleJOIN(c, msg)
	case "PART":
		s.handlePART(c, msg)
	case "PRIVMSG":
		s.handlePRIVMSG(c, msg, false)
	case "NOTICE":
		s.handlePRIVMSG(c, msg, true)
	case "MODE":
		s.handleMODE(c, msg)
	case "TOPIC":
		s.handleTOPIC(c, msg)
	case "NAMES":
		s.handleNAMES(c, msg)
	case "LIST":
		s.handleLIST(c, msg)
	case "KICK":
		s.handleKICK(c, msg)
	case "INVITE":
		s.handleINVITE(c, msg)
	case "WHO":
		s.handleWHO(c, msg)
	case "WHOIS":
		s.handleWHOIS(c, msg)
	case "AWAY":
		s.handleAWAY(c, msg)
	case "ISON":
		s.handleISON(c, msg)
	case "USERHOST":
		s.handleUSERHOST(c, msg)
	case "LUSERS":
		s.handleLUSERS(c)
	case "MOTD":
		s.sendMOTD(c)
	case "VERSION":
		c.SendNumeric(RPL_VERSION, fmt.Sprintf("%s %s :TLS-only modern IRC", serverVersion, s.name))
	case "TIME":
		c.SendNumeric(RPL_TIME, fmt.Sprintf("%s :%s", s.name, time.Now().Format(time.RFC1123)))
	case "OPER":
		s.handleOPER(c, msg)
	case "KILL":
		s.handleKILL(c, msg)
	case "CHATHISTORY":
		s.handleCHATHISTORY(c, msg)
	case "IDENTITY":
		s.handleIDENTITY(c, msg)
	case "METADATA":
		s.handleMETADATA(c, msg)
	case "MONITOR":
		s.handleMONITOR(c, msg)
	case "WATCH":
		s.handleWATCH(c, msg)
	default:
		c.SendNumeric(ERR_UNKNOWNCOMMAND, fmt.Sprintf("%s :Unknown command", msg.Command))
	}
}

func (s *Server) handleCAP(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "CAP :Not enough parameters")
		return
	}

	subcmd := strings.ToUpper(msg.Params[0])
	switch subcmd {
	case "LS":
		c.capNeg = true
		var caps []string
		for cap := range s.caps {
			// SASL includes available mechanisms
			if cap == "sasl" {
				caps = append(caps, "sasl=EXTERNAL,PLAIN")
			} else {
				caps = append(caps, cap)
			}
		}
		sort.Strings(caps)
		c.Send(fmt.Sprintf(":%s CAP * LS :%s", s.name, strings.Join(caps, " ")))

	case "REQ":
		if len(msg.Params) < 2 {
			return
		}
		requested := strings.Fields(msg.Trailing())
		var ack, nak []string
		for _, cap := range requested {
			remove := strings.HasPrefix(cap, "-")
			capName := strings.TrimPrefix(cap, "-")
			if s.caps[capName] {
				if remove {
					delete(c.caps, capName)
				} else {
					c.caps[capName] = true
				}
				ack = append(ack, cap)
			} else {
				nak = append(nak, cap)
			}
		}
		if len(ack) > 0 {
			c.Send(fmt.Sprintf(":%s CAP * ACK :%s", s.name, strings.Join(ack, " ")))
		}
		if len(nak) > 0 {
			c.Send(fmt.Sprintf(":%s CAP * NAK :%s", s.name, strings.Join(nak, " ")))
		}

	case "END":
		c.capNeg = false
		s.tryRegister(c)

	case "LIST":
		var caps []string
		for cap := range c.caps {
			caps = append(caps, cap)
		}
		c.Send(fmt.Sprintf(":%s CAP * LIST :%s", s.name, strings.Join(caps, " ")))
	}
}

func (s *Server) handlePASS(c *Client, msg *Message) {
	if c.registered {
		c.SendNumeric(ERR_ALREADYREGISTRED, ":You may not reregister")
		return
	}
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "PASS :Not enough parameters")
		return
	}
	c.pass = msg.Params[0]
}

func (s *Server) handleNICK(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NONICKNAMEGIVEN, ":No nickname given")
		return
	}

	nick := msg.Params[0]
	if len(nick) > maxNickLen {
		nick = nick[:maxNickLen]
	}
	if !isValidNick(nick) {
		c.SendNumeric(ERR_ERRONEUSNICKNAME, fmt.Sprintf("%s :Erroneous nickname", nick))
		return
	}

	s.mu.Lock()
	existing := s.clients[strings.ToLower(nick)]
	if existing != nil && existing != c {
		s.mu.Unlock()
		c.SendNumeric(ERR_NICKNAMEINUSE, fmt.Sprintf("%s :Nickname is already in use", nick))
		return
	}

	c.mu.Lock()
	oldNick := c.nick
	c.nick = nick
	c.mu.Unlock()

	if oldNick != "" {
		delete(s.clients, strings.ToLower(oldNick))
	}
	s.clients[strings.ToLower(nick)] = c
	s.mu.Unlock()

	// get channels for nick change broadcast
	c.mu.RLock()
	chans := make([]*Channel, 0, len(c.channels))
	for _, ch := range c.channels {
		chans = append(chans, ch)
	}
	c.mu.RUnlock()

	if c.registered && oldNick != nick {
		// notify client
		c.Send(fmt.Sprintf(":%s!%s@%s NICK %s", oldNick, c.user, c.hostname, nick))

		// notify all channels
		for _, ch := range chans {
			select {
			case ch.events <- evNickChange{client: c, oldNick: oldNick, newNick: nick}:
			default:
			}
		}

		// Broadcast NickChange to federation
		if s.federation != nil {
			s.federation.BroadcastNickChange(c, oldNick, nick)
		}
	}

	if !c.registered {
		s.tryRegister(c)
	}
}

func (s *Server) handleUSER(c *Client, msg *Message) {
	if c.registered {
		c.SendNumeric(ERR_ALREADYREGISTRED, ":You may not reregister")
		return
	}
	if len(msg.Params) < 4 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "USER :Not enough parameters")
		return
	}

	c.user = msg.Params[0]
	c.realname = msg.Trailing()

	// check password with constant-time comparison
	if s.password != "" && subtle.ConstantTimeCompare([]byte(c.pass), []byte(s.password)) != 1 {
		c.SendNumeric(ERR_PASSWDMISMATCH, ":Password incorrect")
		s.removeClient(c)
		return
	}

	s.tryRegister(c)
}

func (s *Server) tryRegister(c *Client) {
	c.mu.RLock()
	nick := c.nick
	c.mu.RUnlock()

	if c.registered || c.capNeg || nick == "" || c.user == "" {
		return
	}

	c.registered = true
	c.SendNumeric(RPL_WELCOME, fmt.Sprintf(":Welcome to the %s IRC Network %s", s.network, c.Prefix()))
	c.SendNumeric(RPL_YOURHOST, fmt.Sprintf(":Your host is %s, running version %s", s.name, serverVersion))
	c.SendNumeric(RPL_CREATED, fmt.Sprintf(":This server was created %s", s.created.Format(time.RFC1123)))
	c.SendNumeric(RPL_MYINFO, fmt.Sprintf("%s %s iowrs biklmnopstv bklov", s.name, serverVersion))
	c.SendNumeric(RPL_ISUPPORT, "CASEMAPPING=ascii CHANTYPES=# CHANMODES=b,k,l,imnpst NICKLEN=30 CHANNELLEN=50 TOPICLEN=390 PREFIX=(ov)@+ MONITOR=100 WATCH=100 NETWORK="+s.network+" CHATHISTORY=500 :are supported by this server")
	s.handleLUSERS(c)
	s.sendMOTD(c)

	// Broadcast UserOnline to federation
	if s.federation != nil {
		s.federation.BroadcastUserOnline(c)
	}

	// Notify MONITOR/WATCH watchers
	s.notifyWatchers(c, true)

	// Auto-join default channel
	s.handleJOIN(c, &Message{Command: "JOIN", Params: []string{"##"}})
}

// notifyWatchers sends MONITOR/WATCH notifications when a user comes online or goes offline
func (s *Server) notifyWatchers(target *Client, online bool) {
	targetNick := target.Nick()
	targetNickLower := strings.ToLower(targetNick)

	s.mu.RLock()
	clients := make([]*Client, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.RUnlock()

	for _, c := range clients {
		if c == target {
			continue
		}
		c.mu.RLock()
		inMonitor := c.monitor[targetNickLower]
		inWatch := c.watch[targetNickLower]
		c.mu.RUnlock()

		if inMonitor {
			if online {
				c.SendNumeric(RPL_MONONLINE, ":"+targetNick)
			} else {
				c.SendNumeric(RPL_MONOFFLINE, ":"+targetNick)
			}
		}
		if inWatch {
			target.mu.RLock()
			if online {
				c.SendNumeric(RPL_LOGON, fmt.Sprintf("%s %s %s %d :logged on", targetNick, target.user, target.hostname, target.signon.Unix()))
			} else {
				c.SendNumeric(RPL_LOGOFF, fmt.Sprintf("%s %s %s %d :logged off", targetNick, target.user, target.hostname, target.signon.Unix()))
			}
			target.mu.RUnlock()
		}
	}
}

func (s *Server) handleLUSERS(c *Client) {
	s.mu.RLock()
	users := len(s.clients)
	chans := len(s.channels)
	s.mu.RUnlock()

	c.SendNumeric(RPL_LUSERCLIENT, fmt.Sprintf(":There are %d users and 0 invisible on 1 server", users))
	c.SendNumeric(RPL_LUSEROP, "0 :operator(s) online")
	c.SendNumeric(RPL_LUSERCHANNELS, fmt.Sprintf("%d :channels formed", chans))
	c.SendNumeric(RPL_LUSERME, fmt.Sprintf(":I have %d clients and 1 server", users))
}

func (s *Server) sendMOTD(c *Client) {
	// Collect MOTD from network (federation) and local sources
	var networkMOTD []string
	if s.federation != nil && s.federation.discovery != nil {
		networkMOTD = s.federation.discovery.GetMOTD()
	}

	if len(networkMOTD) == 0 && len(s.motd) == 0 {
		c.SendNumeric(ERR_NOMOTD, ":MOTD File is missing")
		return
	}

	c.SendNumeric(RPL_MOTDSTART, fmt.Sprintf(":- %s Message of the day -", s.name))

	// Network MOTD first
	for _, line := range networkMOTD {
		c.SendNumeric(RPL_MOTD, ":- "+line)
	}

	// Separator if both exist
	if len(networkMOTD) > 0 && len(s.motd) > 0 {
		c.SendNumeric(RPL_MOTD, ":- ")
		c.SendNumeric(RPL_MOTD, ":- === Local Server Info ===")
		c.SendNumeric(RPL_MOTD, ":- ")
	}

	// Local MOTD
	for _, line := range s.motd {
		c.SendNumeric(RPL_MOTD, ":- "+line)
	}

	c.SendNumeric(RPL_ENDOFMOTD, ":End of MOTD command")
}

func (s *Server) handleQUIT(c *Client, msg *Message) {
	reason := "Quit"
	if len(msg.Params) > 0 {
		reason = msg.Trailing()
	}

	c.mu.RLock()
	chans := make([]*Channel, 0, len(c.channels))
	for _, ch := range c.channels {
		chans = append(chans, ch)
	}
	c.mu.RUnlock()

	// notify channels via events
	for _, ch := range chans {
		select {
		case ch.events <- evQuit{client: c, reason: reason}:
		default:
		}
	}

	c.Send(fmt.Sprintf("ERROR :Closing Link: %s (%s)", c.hostname, reason))
	s.removeClient(c)
}

func (s *Server) handlePING(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		return
	}
	c.Send(fmt.Sprintf(":%s PONG %s :%s", s.name, s.name, msg.Params[0]))
}

func (s *Server) handleJOIN(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "JOIN :Not enough parameters")
		return
	}

	if msg.Params[0] == "0" {
		// leave all channels
		c.mu.RLock()
		chans := make([]*Channel, 0, len(c.channels))
		for _, ch := range c.channels {
			chans = append(chans, ch)
		}
		c.mu.RUnlock()
		for _, ch := range chans {
			ch.trySendChanEvent(evPart{client: c, reason: "Leaving all channels"})
		}
		return
	}

	channels := strings.Split(msg.Params[0], ",")
	var keys []string
	if len(msg.Params) > 1 {
		keys = strings.Split(msg.Params[1], ",")
	}

	for i, name := range channels {
		if !isValidChannel(name) {
			c.SendNumeric(ERR_BADCHANMASK, fmt.Sprintf("%s :Bad Channel Mask", name))
			continue
		}
		var key string
		if i < len(keys) {
			key = keys[i]
		}
		ch := s.getOrCreateChannel(name)
		ch.trySendChanEvent(evJoin{client: c, key: key})
	}
}

func (s *Server) handlePART(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "PART :Not enough parameters")
		return
	}

	reason := ""
	if len(msg.Params) > 1 {
		reason = msg.Trailing()
	}

	for _, name := range strings.Split(msg.Params[0], ",") {
		ch := s.getChannel(name)
		if ch == nil {
			c.SendNumeric(ERR_NOSUCHCHANNEL, fmt.Sprintf("%s :No such channel", name))
			continue
		}
		ch.trySendChanEvent(evPart{client: c, reason: reason})
	}
}

func (s *Server) handlePRIVMSG(c *Client, msg *Message, isNotice bool) {
	cmd := "PRIVMSG"
	if isNotice {
		cmd = "NOTICE"
	}

	if len(msg.Params) == 0 {
		if !isNotice {
			c.SendNumeric(ERR_NORECIPIENT, fmt.Sprintf(":No recipient given (%s)", cmd))
		}
		return
	}
	if len(msg.Params) < 2 {
		if !isNotice {
			c.SendNumeric(ERR_NOTEXTTOSEND, ":No text to send")
		}
		return
	}

	targets := strings.Split(msg.Params[0], ",")
	text := msg.Trailing()

	if len(targets) > maxTargets {
		c.SendNumeric(ERR_TOOMANYTARGETS, fmt.Sprintf("%s :Too many targets", msg.Params[0]))
		return
	}

	// Generate message tags for this message
	msgID := s.ircv3.msgIDGen.Next()
	serverTime := ServerTime()

	c.mu.RLock()
	account := c.account
	did := c.did
	c.mu.RUnlock()

	for _, target := range targets {
		if isValidChannel(target) {
			ch := s.getChannel(target)
			if ch == nil {
				if !isNotice {
					c.SendNumeric(ERR_NOSUCHCHANNEL, fmt.Sprintf("%s :No such channel", target))
				}
				continue
			}
			// Pass message info through event for channel actor to handle
			ch.trySendChanEvent(evMessage{
				client:   c,
				text:     text,
				isNotice: isNotice,
				msgID:    msgID,
				time:     serverTime,
				account:  account,
				did:      did,
			})

			// Echo to sender if they have echo-message cap
			if c.caps["echo-message"] {
				tags := s.buildMsgTags(c, msgID, serverTime, account, did)
				line := fmt.Sprintf(":%s %s %s :%s", c.Prefix(), cmd, target, text)
				s.ircv3.SendWithTags(c, tags, line)
			}

			// Store in history
			s.history.StoreChannelMessage(StoredMessage{
				MsgID:    msgID,
				Time:     time.Now(),
				Prefix:   c.Prefix(),
				Account:  account,
				DID:      did,
				Command:  cmd,
				Target:   target,
				Text:     text,
				IsNotice: isNotice,
			})
		} else {
			tgt := s.getClient(target)
			if tgt == nil {
				// Check if target is a remote user
				if s.federation != nil {
					ru := s.federation.GetRemoteUser(target)
					if ru != nil {
						// Send via federation
						if isNotice {
							s.federation.BroadcastNotice(c, "", ru.URN, text)
						} else {
							s.federation.BroadcastPrivateMessage(c, ru.URN, text)
						}

						// Echo to sender if they have echo-message cap
						if c.caps["echo-message"] {
							echoTags := s.buildMsgTags(c, msgID, serverTime, account, did)
							echoLine := fmt.Sprintf(":%s %s %s :%s", c.Prefix(), cmd, target, text)
							s.ircv3.SendWithTags(c, echoTags, echoLine)
						}
						continue
					}
				}

				if !isNotice {
					c.SendNumeric(ERR_NOSUCHNICK, fmt.Sprintf("%s :No such nick/channel", target))
				}
				continue
			}

			if away := tgt.Away(); away != "" && !isNotice {
				c.SendNumeric(RPL_AWAY, fmt.Sprintf("%s :%s", tgt.Nick(), away))
			}

			// Send to recipient with tags
			tags := s.buildMsgTags(tgt, msgID, serverTime, account, did)
			line := fmt.Sprintf(":%s %s %s :%s", c.Prefix(), cmd, tgt.Nick(), text)
			s.ircv3.SendWithTags(tgt, tags, line)

			// Echo to sender if they have echo-message cap
			if c.caps["echo-message"] {
				echoTags := s.buildMsgTags(c, msgID, serverTime, account, did)
				echoLine := fmt.Sprintf(":%s %s %s :%s", c.Prefix(), cmd, target, text)
				s.ircv3.SendWithTags(c, echoTags, echoLine)
			}

			// Store in DM history
			s.history.StoreDMMessage(c.Nick(), tgt.Nick(), StoredMessage{
				MsgID:    msgID,
				Time:     time.Now(),
				Prefix:   c.Prefix(),
				Account:  account,
				DID:      did,
				Command:  cmd,
				Target:   target,
				Text:     text,
				IsNotice: isNotice,
			})
		}
	}
}

// buildMsgTags creates IRCv3 tags filtered by client capabilities
func (s *Server) buildMsgTags(recipient *Client, msgID, serverTime, account, did string) map[string]string {
	tags := make(map[string]string)
	if recipient.caps["message-ids"] {
		tags["msgid"] = msgID
	}
	if recipient.caps["server-time"] {
		tags["time"] = serverTime
	}
	if recipient.caps["account-tag"] && account != "" {
		tags["account"] = account
	}
	if recipient.caps["identity"] && did != "" {
		tags["did"] = did
	}
	return tags
}

func (s *Server) handleMODE(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "MODE :Not enough parameters")
		return
	}

	target := msg.Params[0]
	if isValidChannel(target) {
		s.handleChannelMode(c, msg)
	} else {
		s.handleUserMode(c, msg)
	}
}

func (s *Server) handleUserMode(c *Client, msg *Message) {
	target := msg.Params[0]
	if !strings.EqualFold(target, c.Nick()) {
		c.SendNumeric(ERR_USERSDONTMATCH, ":Cannot change mode for other users")
		return
	}

	if len(msg.Params) == 1 {
		c.mu.RLock()
		var modes string
		for m := range c.modes {
			modes += string(m)
		}
		c.mu.RUnlock()
		if modes == "" {
			modes = "+"
		} else {
			modes = "+" + modes
		}
		c.SendNumeric(RPL_UMODEIS, modes)
		return
	}

	modeStr := msg.Params[1]
	add := true
	var changes string
	c.mu.Lock()
	for _, ch := range modeStr {
		switch ch {
		case '+':
			add = true
		case '-':
			add = false
		case 'i', 'w', 'r', 's':
			if add {
				if !c.modes[ch] {
					c.modes[ch] = true
					changes += "+" + string(ch)
				}
			} else {
				if c.modes[ch] {
					delete(c.modes, ch)
					changes += "-" + string(ch)
				}
			}
		case 'o':
			if !add && c.modes['o'] {
				delete(c.modes, 'o')
				changes += "-o"
			}
		default:
			c.SendNumeric(ERR_UMODEUNKNOWNFLAG, ":Unknown MODE flag")
		}
	}
	c.mu.Unlock()

	if changes != "" {
		c.SendFrom(c.Prefix(), "MODE", c.Nick(), changes)
	}
}

func (s *Server) handleChannelMode(c *Client, msg *Message) {
	name := msg.Params[0]
	ch := s.getChannel(name)
	if ch == nil {
		c.SendNumeric(ERR_NOSUCHCHANNEL, fmt.Sprintf("%s :No such channel", name))
		return
	}

	var modeStr string
	var params []string
	if len(msg.Params) > 1 {
		modeStr = msg.Params[1]
		params = msg.Params[2:]
	}

	ch.trySendChanEvent(evMode{client: c, modeStr: modeStr, params: params})
}

func (s *Server) handleTOPIC(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "TOPIC :Not enough parameters")
		return
	}

	ch := s.getChannel(msg.Params[0])
	if ch == nil {
		c.SendNumeric(ERR_NOSUCHCHANNEL, fmt.Sprintf("%s :No such channel", msg.Params[0]))
		return
	}

	var newTopic *string
	if len(msg.Params) > 1 {
		t := msg.Trailing()
		newTopic = &t
	}

	ch.trySendChanEvent(evTopic{client: c, newTopic: newTopic})
}

func (s *Server) handleNAMES(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(RPL_ENDOFNAMES, "* :End of NAMES list")
		return
	}

	for _, name := range strings.Split(msg.Params[0], ",") {
		ch := s.getChannel(name)
		if ch == nil {
			c.SendNumeric(RPL_ENDOFNAMES, fmt.Sprintf("%s :End of NAMES list", name))
			continue
		}
		ch.trySendChanEvent(evNames{client: c})
	}
}

func (s *Server) handleLIST(c *Client, msg *Message) {
	s.mu.RLock()
	chans := make([]*Channel, 0, len(s.channels))
	for _, ch := range s.channels {
		chans = append(chans, ch)
	}
	s.mu.RUnlock()

	for _, ch := range chans {
		reply := make(chan int, 1)
		if !ch.sendChanEventWithTimeout(evListInfo{reply: reply}, 5*time.Second) {
			continue // skip this channel if event send timed out
		}
		count := <-reply
		c.SendNumeric(RPL_LIST, fmt.Sprintf("%s %d :", ch.name, count))
	}
	c.SendNumeric(RPL_LISTEND, ":End of LIST")
}

func (s *Server) handleKICK(c *Client, msg *Message) {
	if len(msg.Params) < 2 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "KICK :Not enough parameters")
		return
	}

	ch := s.getChannel(msg.Params[0])
	if ch == nil {
		c.SendNumeric(ERR_NOSUCHCHANNEL, fmt.Sprintf("%s :No such channel", msg.Params[0]))
		return
	}

	target := s.getClient(msg.Params[1])
	if target == nil {
		c.SendNumeric(ERR_NOSUCHNICK, fmt.Sprintf("%s :No such nick/channel", msg.Params[1]))
		return
	}

	reason := target.Nick()
	if len(msg.Params) > 2 {
		reason = msg.Trailing()
	}

	ch.trySendChanEvent(evKick{client: c, target: target, reason: reason})
}

func (s *Server) handleINVITE(c *Client, msg *Message) {
	if len(msg.Params) < 2 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "INVITE :Not enough parameters")
		return
	}

	target := s.getClient(msg.Params[0])
	if target == nil {
		c.SendNumeric(ERR_NOSUCHNICK, fmt.Sprintf("%s :No such nick/channel", msg.Params[0]))
		return
	}

	ch := s.getChannel(msg.Params[1])
	if ch == nil {
		c.SendNumeric(ERR_NOSUCHCHANNEL, fmt.Sprintf("%s :No such channel", msg.Params[1]))
		return
	}

	ch.trySendChanEvent(evInvite{client: c, target: target})
}

func (s *Server) handleWHO(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(RPL_ENDOFWHO, "* :End of WHO list")
		return
	}

	mask := msg.Params[0]
	if isValidChannel(mask) {
		ch := s.getChannel(mask)
		if ch == nil {
			c.SendNumeric(RPL_ENDOFWHO, fmt.Sprintf("%s :End of WHO list", mask))
			return
		}
		ch.trySendChanEvent(evWho{client: c})
	} else {
		target := s.getClient(mask)
		if target != nil {
			flags := "H"
			if target.Away() != "" {
				flags = "G"
			}
			c.SendNumeric(RPL_WHOREPLY, fmt.Sprintf("* %s %s %s %s %s :0 %s",
				target.user, target.hostname, s.name, target.Nick(), flags, target.realname))
		}
		c.SendNumeric(RPL_ENDOFWHO, fmt.Sprintf("%s :End of WHO list", mask))
	}
}

func (s *Server) handleWHOIS(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NONICKNAMEGIVEN, ":No nickname given")
		return
	}

	nick := msg.Params[0]
	if len(msg.Params) > 1 {
		nick = msg.Params[1]
	}

	target := s.getClient(nick)
	if target == nil {
		// Check for remote user via federation
		if s.federation != nil {
			ru := s.federation.GetRemoteUser(nick)
			if ru != nil {
				s.sendRemoteWhois(c, ru)
				return
			}
		}
		c.SendNumeric(ERR_NOSUCHNICK, fmt.Sprintf("%s :No such nick/channel", nick))
		c.SendNumeric(RPL_ENDOFWHOIS, fmt.Sprintf("%s :End of WHOIS list", nick))
		return
	}

	c.SendNumeric(RPL_WHOISUSER, fmt.Sprintf("%s %s %s * :%s",
		target.Nick(), target.user, target.hostname, target.realname))
	c.SendNumeric(RPL_WHOISSERVER, fmt.Sprintf("%s %s :%s", target.Nick(), s.name, s.network))

	// Show account info if logged in
	target.mu.RLock()
	account := target.account
	did := target.did
	identityJSON := target.identity
	identityVerified := target.identityVerified
	target.mu.RUnlock()
	if account != "" {
		c.SendNumeric("330", fmt.Sprintf("%s %s :is logged in as", target.Nick(), account))
	}

	// Show identity info in WHOIS (per IDENTITY.md spec)
	if identityJSON != "" {
		// Parse the identity document to extract fields
		var doc IdentityDocument
		if err := json.Unmarshal([]byte(identityJSON), &doc); err == nil {
			// DID line
			c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :DID %s", target.Nick(), doc.ID))
			// Verified line (only true if this server verified the proof)
			c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :Verified %t", target.Nick(), identityVerified))
			// AKA lines for each alsoKnownAs
			for _, aka := range doc.AlsoKnownAs {
				c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :AKA %s", target.Nick(), aka))
			}
			// Homepage from LinkedDomains service
			for _, svc := range doc.Service {
				if svc.Type == "LinkedDomains" {
					c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :Homepage %s", target.Nick(), svc.ServiceEndpoint))
				}
			}
		}
	} else if did != "" && c.caps["identity"] {
		// Fallback: show basic DID from SASL if no full identity
		c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :DID %s", target.Nick(), did))
	}

	// channels - snapshot channel list, then query each channel's goroutine for modes
	s.mu.RLock()
	channelList := make([]*Channel, 0, len(target.channels))
	for _, ch := range target.channels {
		channelList = append(channelList, ch)
	}
	s.mu.RUnlock()

	var chans []string
	for _, ch := range channelList {
		// ponytail: skip secret/private check for simplicity
		prefix := ""
		reply := make(chan string, 1)
		if !ch.sendChanEventWithTimeout(evMemberModes{target: target, reply: reply}, 5*time.Second) {
			continue // skip this channel if event send timed out
		}
		modes := <-reply
		if strings.Contains(modes, "o") {
			prefix = "@"
		} else if strings.Contains(modes, "v") {
			prefix = "+"
		}
		chans = append(chans, prefix+ch.name)
	}

	if len(chans) > 0 {
		c.SendNumeric(RPL_WHOISCHANNELS, fmt.Sprintf("%s :%s", target.Nick(), strings.Join(chans, " ")))
	}

	target.mu.RLock()
	isOper := target.modes['o']
	away := target.away
	lastActive := target.lastActive
	target.mu.RUnlock()

	if isOper {
		c.SendNumeric(RPL_WHOISOPERATOR, fmt.Sprintf("%s :is an IRC operator", target.Nick()))
	}

	if away != "" {
		c.SendNumeric(RPL_AWAY, fmt.Sprintf("%s :%s", target.Nick(), away))
	}

	idle := int(time.Since(lastActive).Seconds())
	c.SendNumeric(RPL_WHOISIDLE, fmt.Sprintf("%s %d %d :seconds idle, signon time",
		target.Nick(), idle, target.signon.Unix()))
	c.SendNumeric(RPL_ENDOFWHOIS, fmt.Sprintf("%s :End of WHOIS list", target.Nick()))
}

// sendRemoteWhois sends WHOIS response for a remote user (via federation)
func (s *Server) sendRemoteWhois(c *Client, ru *RemoteUser) {
	c.SendNumeric(RPL_WHOISUSER, fmt.Sprintf("%s %s %s * :%s",
		ru.Nick, ru.Ident, ru.Host, ru.Realname))
	c.SendNumeric(RPL_WHOISSERVER, fmt.Sprintf("%s %s :federated user", ru.Nick, ru.Server))

	// Show identity info if present
	// Remote identities are NOT verified by this server - the origin server verified them
	if ru.Identity != "" {
		var doc IdentityDocument
		if err := json.Unmarshal([]byte(ru.Identity), &doc); err == nil {
			// DID line
			c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :DID %s", ru.Nick, doc.ID))
			// Verified false - this server did not verify the proof; origin server did
			c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :Verified false", ru.Nick))
			// AKA lines
			for _, aka := range doc.AlsoKnownAs {
				c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :AKA %s", ru.Nick, aka))
			}
			// Homepage from LinkedDomains service
			for _, svc := range doc.Service {
				if svc.Type == "LinkedDomains" {
					c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :Homepage %s", ru.Nick, svc.ServiceEndpoint))
				}
			}
		}
	} else if ru.DID != "" && c.caps["identity"] {
		// Fallback: show basic DID
		c.SendNumeric(RPL_WHOISIDENTITY, fmt.Sprintf("%s :DID %s", ru.Nick, ru.DID))
	}

	c.SendNumeric(RPL_ENDOFWHOIS, fmt.Sprintf("%s :End of WHOIS list", ru.Nick))
}

func (s *Server) handleAWAY(c *Client, msg *Message) {
	c.mu.Lock()
	if len(msg.Params) == 0 {
		c.away = ""
		c.mu.Unlock()
		c.SendNumeric(RPL_UNAWAY, ":You are no longer marked as being away")
		return
	}

	c.away = msg.Trailing()
	c.mu.Unlock()
	c.SendNumeric(RPL_NOWAWAY, ":You have been marked as being away")

	// notify channels with away-notify via channel events
	c.mu.RLock()
	chans := make([]*Channel, 0, len(c.channels))
	for _, ch := range c.channels {
		chans = append(chans, ch)
	}
	c.mu.RUnlock()

	awayMsg := c.Away()
	for _, ch := range chans {
		select {
		case ch.events <- evAwayNotify{client: c, awayMsg: awayMsg}:
		default:
			// channel event queue full, skip
		}
	}
}

func (s *Server) handleISON(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "ISON :Not enough parameters")
		return
	}

	var online []string
	for _, nick := range msg.Params {
		if s.getClient(nick) != nil {
			online = append(online, nick)
		}
	}
	c.SendNumeric(RPL_ISON, ":"+strings.Join(online, " "))
}

func (s *Server) handleUSERHOST(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "USERHOST :Not enough parameters")
		return
	}

	var results []string
	for i, nick := range msg.Params {
		if i >= 5 {
			break
		}
		target := s.getClient(nick)
		if target != nil {
			target.mu.RLock()
			oper := ""
			if target.modes['o'] {
				oper = "*"
			}
			away := "+"
			if target.away != "" {
				away = "-"
			}
			target.mu.RUnlock()
			results = append(results, fmt.Sprintf("%s%s=%s%s@%s",
				target.Nick(), oper, away, target.user, target.hostname))
		}
	}
	c.SendNumeric(RPL_USERHOST, ":"+strings.Join(results, " "))
}

const monitorLimit = 100 // max nicks per client

func (s *Server) handleMONITOR(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "MONITOR :Not enough parameters")
		return
	}

	cmd := strings.ToUpper(msg.Params[0])
	switch cmd {
	case "+":
		// Add nicks to monitor list
		if len(msg.Params) < 2 {
			return
		}
		nicks := strings.Split(msg.Params[1], ",")
		var online, offline []string
		c.mu.Lock()
		for _, nick := range nicks {
			nick = strings.TrimSpace(nick)
			if nick == "" {
				continue
			}
			if len(c.monitor) >= monitorLimit {
				c.mu.Unlock()
				c.SendNumeric(ERR_MONLISTFULL, fmt.Sprintf("%d %s :Monitor list is full", monitorLimit, nick))
				return
			}
			c.monitor[strings.ToLower(nick)] = true
			if target := s.getClient(nick); target != nil {
				online = append(online, target.Nick())
			} else {
				offline = append(offline, nick)
			}
		}
		c.mu.Unlock()
		if len(online) > 0 {
			c.SendNumeric(RPL_MONONLINE, ":"+strings.Join(online, ","))
		}
		if len(offline) > 0 {
			c.SendNumeric(RPL_MONOFFLINE, ":"+strings.Join(offline, ","))
		}

	case "-":
		// Remove nicks from monitor list
		if len(msg.Params) < 2 {
			return
		}
		nicks := strings.Split(msg.Params[1], ",")
		c.mu.Lock()
		for _, nick := range nicks {
			delete(c.monitor, strings.ToLower(strings.TrimSpace(nick)))
		}
		c.mu.Unlock()

	case "C":
		// Clear monitor list
		c.mu.Lock()
		c.monitor = make(map[string]bool)
		c.mu.Unlock()

	case "L":
		// List monitored nicks
		c.mu.RLock()
		nicks := make([]string, 0, len(c.monitor))
		for nick := range c.monitor {
			nicks = append(nicks, nick)
		}
		c.mu.RUnlock()
		if len(nicks) > 0 {
			c.SendNumeric(RPL_MONLIST, ":"+strings.Join(nicks, ","))
		}
		c.SendNumeric(RPL_ENDOFMONLIST, ":End of MONITOR list")

	case "S":
		// Status - report online/offline for all monitored
		c.mu.RLock()
		var online, offline []string
		for nick := range c.monitor {
			if target := s.getClient(nick); target != nil {
				online = append(online, target.Nick())
			} else {
				offline = append(offline, nick)
			}
		}
		c.mu.RUnlock()
		if len(online) > 0 {
			c.SendNumeric(RPL_MONONLINE, ":"+strings.Join(online, ","))
		}
		if len(offline) > 0 {
			c.SendNumeric(RPL_MONOFFLINE, ":"+strings.Join(offline, ","))
		}
	}
}

func (s *Server) handleWATCH(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "WATCH :Not enough parameters")
		return
	}

	// WATCH uses +nick/-nick format or single letter commands
	arg := msg.Params[0]

	switch strings.ToUpper(arg) {
	case "L", "l":
		// List watched nicks with status
		c.mu.RLock()
		for nick := range c.watch {
			if target := s.getClient(nick); target != nil {
				target.mu.RLock()
				c.SendNumeric(RPL_NOWON, fmt.Sprintf("%s %s %s %d :is online", target.Nick(), target.user, target.hostname, target.signon.Unix()))
				target.mu.RUnlock()
			} else {
				c.SendNumeric(RPL_NOWOFF, fmt.Sprintf("%s * * 0 :is offline", nick))
			}
		}
		c.mu.RUnlock()
		c.SendNumeric(RPL_ENDOFWATCHLIST, ":End of WATCH l")

	case "C", "c":
		// Clear watch list
		c.mu.Lock()
		c.watch = make(map[string]bool)
		c.mu.Unlock()

	case "S", "s":
		// Stats
		c.mu.RLock()
		count := len(c.watch)
		c.mu.RUnlock()
		c.SendNumeric(RPL_WATCHSTAT, fmt.Sprintf(":You have %d entries in your watch list", count))

	default:
		// +nick or -nick format
		for _, param := range msg.Params {
			if len(param) < 2 {
				continue
			}
			op := param[0]
			nick := param[1:]
			nickLower := strings.ToLower(nick)

			switch op {
			case '+':
				c.mu.Lock()
				c.watch[nickLower] = true
				c.mu.Unlock()
				if target := s.getClient(nick); target != nil {
					target.mu.RLock()
					c.SendNumeric(RPL_NOWON, fmt.Sprintf("%s %s %s %d :is online", target.Nick(), target.user, target.hostname, target.signon.Unix()))
					target.mu.RUnlock()
				} else {
					c.SendNumeric(RPL_NOWOFF, fmt.Sprintf("%s * * 0 :is offline", nick))
				}
			case '-':
				c.mu.Lock()
				delete(c.watch, nickLower)
				c.mu.Unlock()
				c.SendNumeric(RPL_WATCHOFF, fmt.Sprintf("%s * * 0 :stopped watching", nick))
			}
		}
	}
}

func (s *Server) handleOPER(c *Client, msg *Message) {
	if len(msg.Params) < 2 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "OPER :Not enough parameters")
		return
	}

	if s.operPass == "" || subtle.ConstantTimeCompare([]byte(msg.Params[1]), []byte(s.operPass)) != 1 {
		c.SendNumeric(ERR_PASSWDMISMATCH, ":Password incorrect")
		return
	}

	c.mu.Lock()
	c.modes['o'] = true
	c.mu.Unlock()

	c.SendNumeric(RPL_YOUREOPER, ":You are now an IRC operator")
	c.SendFrom(c.Prefix(), "MODE", c.Nick(), "+o")
}

func (s *Server) handleKILL(c *Client, msg *Message) {
	c.mu.RLock()
	isOper := c.modes['o']
	c.mu.RUnlock()

	if !isOper {
		c.SendNumeric(ERR_NOPRIVILEGES, ":Permission Denied- You're not an IRC operator")
		return
	}

	if len(msg.Params) < 2 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "KILL :Not enough parameters")
		return
	}

	target := s.getClient(msg.Params[0])
	if target == nil {
		c.SendNumeric(ERR_NOSUCHNICK, fmt.Sprintf("%s :No such nick/channel", msg.Params[0]))
		return
	}

	reason := msg.Trailing()
	target.Send(fmt.Sprintf(":%s KILL %s :%s", c.Prefix(), target.Nick(), reason))
	s.removeClient(target)
}

func (s *Server) handleCHATHISTORY(c *Client, msg *Message) {
	if !c.caps["draft/chathistory"] {
		c.SendNumeric(ERR_UNKNOWNCOMMAND, "CHATHISTORY :Unknown command")
		return
	}
	// ponytail: no label tracking for chathistory for now
	s.chathistory.Handle(c, msg, "")
}

// RPL_IDENTITYCHALLENGE numeric for identity challenges
// Using 761 (vendor-specific range) to avoid conflict with 903 (RPL_SASLSUCCESS)
const RPL_IDENTITYCHALLENGE = "761"

func (s *Server) handleIDENTITY(c *Client, msg *Message) {
	if len(msg.Params) == 0 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "IDENTITY :Not enough parameters")
		return
	}

	subcmd := strings.ToUpper(msg.Params[0])
	switch subcmd {
	case "CHALLENGE":
		// Rate limit: max 1 challenge per 10 seconds per client
		const challengeRateLimit = 10 * time.Second
		c.mu.Lock()
		if time.Since(c.lastChallengeTime) < challengeRateLimit {
			c.mu.Unlock()
			c.Send(fmt.Sprintf(":%s FAIL IDENTITY RATE_LIMITED :Too many challenge requests; try again later", s.name))
			return
		}
		c.lastChallengeTime = time.Now()
		c.mu.Unlock()

		// Generate challenge: irc:<nick>@<server>:<unix-timestamp>
		challenge := GenerateChallenge(c.Nick(), s.name)
		s.challenges.Set(c, challenge.Raw)
		c.SendNumeric(RPL_IDENTITYCHALLENGE, fmt.Sprintf(":%s", challenge.Raw))
	default:
		c.SendNumeric(ERR_UNKNOWNCOMMAND, fmt.Sprintf("IDENTITY %s :Unknown subcommand", subcmd))
	}
}

func (s *Server) handleMETADATA(c *Client, msg *Message) {
	if len(msg.Params) < 2 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "METADATA :Not enough parameters")
		return
	}

	target := msg.Params[0]
	subcmd := strings.ToUpper(msg.Params[1])

	switch subcmd {
	case "SET":
		s.handleMetadataSet(c, msg, target)
	case "GET":
		s.handleMetadataGet(c, msg, target)
	case "CLEAR":
		s.handleMetadataClear(c, msg, target)
	case "LIST":
		s.handleMetadataList(c, msg, target)
	default:
		c.Send(fmt.Sprintf(":%s FAIL METADATA INVALID_COMMAND %s :Unknown METADATA subcommand", s.name, subcmd))
	}
}

func (s *Server) handleMetadataSet(c *Client, msg *Message, target string) {
	if target != "*" {
		c.Send(fmt.Sprintf(":%s FAIL METADATA CANNOT_SET %s :Cannot set metadata for other users", s.name, target))
		return
	}

	if len(msg.Params) < 4 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "METADATA SET :Not enough parameters")
		return
	}

	key := strings.ToLower(msg.Params[2])
	value := msg.Trailing()

	// Check visibility parameter if present
	// Format: METADATA <target> SET <key> [<visibility>] :<value>
	// When visibility is present, we have 5+ params: target, SET, key, visibility, value
	if len(msg.Params) > 4 {
		visibility := msg.Params[3]
		// Per IDENTITY.md: "The identity key is public; servers MUST NOT allow setting it as private"
		if key == "identity" && visibility != "*" {
			c.Send(fmt.Sprintf(":%s FAIL METADATA INVALID_VALUE identity :Identity key must be public (visibility '*')", s.name))
			return
		}
	}

	if key != "identity" {
		c.Send(fmt.Sprintf(":%s FAIL METADATA KEY_NOT_SUPPORTED %s :Key not supported", s.name, key))
		return
	}

	// Reject oversized identity documents to prevent memory exhaustion
	if len(value) > maxIdentitySize {
		c.Send(fmt.Sprintf(":%s FAIL METADATA INVALID_VALUE identity :Identity document too large (max %d bytes)", s.name, maxIdentitySize))
		return
	}

	// Parse and verify the identity document
	var doc IdentityDocument
	if err := json.Unmarshal([]byte(value), &doc); err != nil {
		log.Printf("METADATA SET identity: JSON parse error from %s: %v", c.Nick(), err)
		c.Send(fmt.Sprintf(":%s FAIL METADATA INVALID_VALUE identity :Invalid JSON-LD document", s.name))
		return
	}

	// Get pending challenge
	pendingChallenge := s.challenges.Get(c)
	if pendingChallenge == "" {
		c.Send(fmt.Sprintf(":%s FAIL METADATA INVALID_VALUE identity :No pending challenge; use IDENTITY CHALLENGE first", s.name))
		return
	}

	// Verify the proof's challenge matches the server-issued challenge
	if doc.Proof == nil || doc.Proof.Challenge != pendingChallenge {
		c.Send(fmt.Sprintf(":%s FAIL METADATA INVALID_VALUE identity :Challenge mismatch; proof must use server-issued challenge", s.name))
		return
	}

	// Clear the challenge immediately to enforce one-shot semantics
	// (prevents replay attacks if verification fails)
	s.challenges.Clear(c)

	// Verify the proof
	if err := VerifyIdentityProof(&doc, c.Nick(), s.name); err != nil {
		log.Printf("METADATA SET identity: signature verification failed for %s: %v", c.Nick(), err)
		c.Send(fmt.Sprintf(":%s FAIL METADATA INVALID_VALUE identity :Signature verification failed", s.name))
		return
	}

	// Store identity with verified status
	c.mu.Lock()
	c.identity = value
	c.did = doc.ID
	c.identityVerified = true
	c.mu.Unlock()

	// Send confirmation
	c.SendFrom(s.name, "METADATA", "*", "identity", "*", value)

	// Broadcast identity update to federation
	if s.federation != nil {
		s.federation.BroadcastIdentityUpdate(c, value)
	}
}

func (s *Server) handleMetadataGet(c *Client, msg *Message, target string) {
	if len(msg.Params) < 3 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "METADATA GET :Not enough parameters")
		return
	}

	key := strings.ToLower(msg.Params[2])
	if key != "identity" {
		c.Send(fmt.Sprintf(":%s FAIL METADATA KEY_NOT_SUPPORTED %s :Key not supported", s.name, key))
		return
	}

	var identity string
	var targetNick string

	if target == "*" {
		// Get own identity
		c.mu.RLock()
		identity = c.identity
		targetNick = c.nick
		c.mu.RUnlock()
	} else {
		// Get another user's identity
		targetClient := s.getClient(target)
		if targetClient == nil {
			c.SendNumeric(ERR_NOSUCHNICK, fmt.Sprintf("%s :No such nick/channel", target))
			return
		}
		targetClient.mu.RLock()
		identity = targetClient.identity
		targetNick = targetClient.nick
		targetClient.mu.RUnlock()
	}

	c.SendFrom(s.name, "METADATA", targetNick, "identity", "*", identity)
}

func (s *Server) handleMetadataClear(c *Client, msg *Message, target string) {
	if target != "*" {
		c.Send(fmt.Sprintf(":%s FAIL METADATA CANNOT_SET %s :Cannot clear metadata for other users", s.name, target))
		return
	}

	if len(msg.Params) < 3 {
		c.SendNumeric(ERR_NEEDMOREPARAMS, "METADATA CLEAR :Not enough parameters")
		return
	}

	key := strings.ToLower(msg.Params[2])
	if key != "identity" {
		c.Send(fmt.Sprintf(":%s FAIL METADATA KEY_NOT_SUPPORTED %s :Key not supported", s.name, key))
		return
	}

	// Clear identity
	c.mu.Lock()
	c.identity = ""
	c.did = ""
	c.identityVerified = false
	c.mu.Unlock()

	// Send confirmation (empty value indicates cleared)
	c.SendFrom(s.name, "METADATA", "*", "identity", "*", "")

	// Broadcast identity clear to federation
	if s.federation != nil {
		s.federation.BroadcastIdentityUpdate(c, "")
	}
}

func (s *Server) handleMetadataList(c *Client, msg *Message, target string) {
	var targetClient *Client

	if target == "*" {
		targetClient = c
	} else {
		targetClient = s.getClient(target)
		if targetClient == nil {
			c.SendNumeric(ERR_NOSUCHNICK, fmt.Sprintf("%s :No such nick/channel", target))
			return
		}
	}

	targetClient.mu.RLock()
	hasIdentity := targetClient.identity != ""
	targetNick := targetClient.nick
	targetClient.mu.RUnlock()

	// Send list of keys
	if hasIdentity {
		c.SendFrom(s.name, "METADATA", targetNick, "identity", "*", "")
	}
	c.Send(fmt.Sprintf(":%s %s %s %s :End of metadata", s.name, RPL_METADATAEND, c.Nick(), targetNick))
}

// Validation helpers
func isValidNick(nick string) bool {
	if nick == "" || len(nick) > maxNickLen {
		return false
	}
	first := nick[0]
	if !((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ||
		first == '_' || first == '[' || first == ']' || first == '\\' ||
		first == '^' || first == '{' || first == '}' || first == '|' || first == '`') {
		return false
	}
	for _, r := range nick[1:] {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' ||
			r == '[' || r == ']' || r == '\\' || r == '^' ||
			r == '{' || r == '}' || r == '|' || r == '`') {
			return false
		}
	}
	return true
}

func isValidChannel(name string) bool {
	if len(name) < 2 || len(name) > maxChannelLen {
		return false
	}
	if name[0] != '#' {
		return false
	}
	for _, r := range name {
		if r == ' ' || r == ',' || r == 7 {
			return false
		}
	}
	return true
}

func matchMask(s, mask string) bool {
	// ponytail: simple glob match, upgrade to regex if IRC wildcards need more
	s = strings.ToLower(s)
	mask = strings.ToLower(mask)

	mi, si := 0, 0
	starIdx, matchIdx := -1, -1

	for si < len(s) {
		if mi < len(mask) && (mask[mi] == '?' || mask[mi] == s[si]) {
			mi++
			si++
		} else if mi < len(mask) && mask[mi] == '*' {
			starIdx = mi
			matchIdx = si
			mi++
		} else if starIdx != -1 {
			mi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}

	for mi < len(mask) && mask[mi] == '*' {
		mi++
	}
	return mi == len(mask)
}

// runInit handles the --init mode: generates ECDSA for TLS + Ed25519 for federation
func runInit(hostname, admin, addr, dataPath string) error {
	keyFile := dataPath + "/server.key"
	certFile := dataPath + "/server.crt"
	fedKeyFile := dataPath + "/fed.key"

	// Ensure data directory exists
	if err := os.MkdirAll(dataPath, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Check if key already exists
	if _, err := os.Stat(keyFile); err == nil {
		return fmt.Errorf("%s already exists; remove it first to regenerate", keyFile)
	}

	// Generate ECDSA keypair for TLS (P-256 for macOS compatibility)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA keypair: %w", err)
	}

	// Save ECDSA private key
	ecdsaKeyBytes, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ECDSA key: %w", err)
	}
	ecdsaKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: ecdsaKeyBytes,
	})
	if err := os.WriteFile(keyFile, ecdsaKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write server.key: %w", err)
	}

	// Generate Ed25519 keypair for federation signing
	edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	// Save Ed25519 private key
	edKeyBytes, err := x509.MarshalPKCS8PrivateKey(edPrivKey)
	if err != nil {
		return fmt.Errorf("failed to marshal Ed25519 key: %w", err)
	}
	edKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: edKeyBytes,
	})
	if err := os.WriteFile(fedKeyFile, edKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write fed.key: %w", err)
	}

	// Generate self-signed TLS certificate with ECDSA key
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	certHostname := hostname
	if certHostname == "" {
		certHostname = "localhost"
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"IRC Server"},
			CommonName:   certHostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{certHostname},
	}

	// Add IP address if hostname looks like one
	if ip := net.ParseIP(certHostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &ecdsaKey.PublicKey, ecdsaKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write server.crt: %w", err)
	}

	// Extract port from addr
	port := 6697
	if _, portStr, err := net.SplitHostPort(addr); err == nil {
		fmt.Sscanf(portStr, "%d", &port)
	}

	// Output JSON block for servers.json
	displayHostname := hostname
	if displayHostname == "" {
		displayHostname = "localhost"
	}

	pubKeyBase64 := base64.StdEncoding.EncodeToString(edPubKey)

	serverEntry := map[string]interface{}{
		displayHostname: map[string]interface{}{
			"port":   port,
			"pubkey": "ed25519:" + pubKeyBase64,
			"admin":  admin,
		},
	}

	jsonOut, err := json.MarshalIndent(serverEntry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	log.Printf("Generated server.key (ECDSA/TLS), server.crt, and fed.key (Ed25519/federation)")
	log.Printf("Add to servers.json:")
	fmt.Println(string(jsonOut))

	return nil
}

// envOrFlag returns the environment variable value if set, otherwise the flag default.
func envOrFlag(envName, flagVal string) string {
	if v := os.Getenv(envName); v != "" {
		return v
	}
	return flagVal
}

func main() {
	addr := flag.String("addr", ":6697", "Listen address")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS key file")
	dataDir := flag.String("data", "", "Data directory for keys and cache")
	name := flag.String("name", "", "Server name")
	network := flag.String("network", "", "Network name")
	password := flag.String("password", "", "Server password (optional)")
	operPass := flag.String("operpass", "", "Operator password (optional)")
	motdFile := flag.String("motd", "", "MOTD file (optional)")

	// Federation flags
	discoveryURL := flag.String("discovery-url", "", "URL of servers.json for federation (optional)")
	discoveryCache := flag.String("discovery-cache", "", "Local cache path for servers.json")
	discoveryToken := flag.String("discovery-token", "", "GitHub API token for private repos (optional)")
	fedKeyFile := flag.String("fed-key", "", "Ed25519 private key for federation signing")

	// Init mode flags
	initMode := flag.Bool("init", false, "Initialize server keys and certificate")
	initHostname := flag.String("hostname", "", "Server hostname for init mode")
	initAdmin := flag.String("admin", "", "Admin email for init mode")

	flag.Parse()

	// Apply env var fallbacks
	dataPath := envOrFlag("MESHIRCD_DATA", *dataDir)
	if dataPath == "" {
		if _, err := os.Stat("/data"); err == nil {
			dataPath = "/data" // container default
		} else {
			dataPath = "." // local default
		}
	}
	serverName := envOrFlag("MESHIRCD_HOSTNAME", *name)
	if serverName == "" {
		serverName = "irc.local"
	}
	networkName := envOrFlag("MESHIRCD_NETWORK", *network)
	if networkName == "" {
		networkName = "MeshIRCd"
	}
	discURL := envOrFlag("MESHIRCD_DISCOVERY_URL", *discoveryURL)
	discToken := envOrFlag("MESHIRCD_DISCOVERY_TOKEN", *discoveryToken)

	certPath := *certFile
	if certPath == "" {
		certPath = dataPath + "/server.crt"
	}
	keyPath := *keyFile
	if keyPath == "" {
		keyPath = dataPath + "/server.key"
	}

	// Handle init mode
	if *initMode {
		initHost := envOrFlag("MESHIRCD_HOSTNAME", *initHostname)
		initAdm := envOrFlag("MESHIRCD_ADMIN", *initAdmin)
		if err := runInit(initHost, initAdm, *addr, dataPath); err != nil {
			log.Fatalf("Init failed: %v", err)
		}
		return
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("Failed to load TLS cert: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequestClientCert, // Request but don't require for SASL EXTERNAL
	}

	listener, err := tls.Listen("tcp", *addr, config)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	server := newServer(serverName, networkName, *password, *operPass)

	// Load local MOTD: flag > env var > default path
	motdPath := *motdFile
	if motdPath == "" {
		motdPath = os.Getenv("MESHIRCD_MOTD")
	}
	if motdPath == "" {
		// Try default path
		defaultMOTD := dataPath + "/motd.txt"
		if _, err := os.Stat(defaultMOTD); err == nil {
			motdPath = defaultMOTD
		}
	}
	if motdPath != "" {
		data, err := os.ReadFile(motdPath)
		if err == nil {
			server.motd = strings.Split(strings.TrimSpace(string(data)), "\n")
		}
	}

	// Initialize federation if discovery URL is configured
	if discURL != "" {
		cachePath := *discoveryCache
		if cachePath == "" {
			cachePath = dataPath + "/servers.json"
		}

		discovery := NewDiscovery(discURL, cachePath, discToken)

		// Load Ed25519 federation key (separate from TLS cert)
		fedKeyPath := *fedKeyFile
		if fedKeyPath == "" {
			fedKeyPath = dataPath + "/fed.key"
		}

		var edPrivKey ed25519.PrivateKey
		fedKeyData, err := os.ReadFile(fedKeyPath)
		if err != nil {
			log.Printf("Federation key not found at %s; federation disabled", fedKeyPath)
		} else {
			block, _ := pem.Decode(fedKeyData)
			if block == nil {
				log.Printf("Federation key invalid PEM; federation disabled")
			} else {
				key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					log.Printf("Federation key parse error: %v; federation disabled", err)
				} else if k, ok := key.(ed25519.PrivateKey); !ok {
					log.Printf("Federation key not Ed25519 (got %T); federation disabled", key)
				} else {
					edPrivKey = k
				}
			}
		}

		if edPrivKey != nil {
			fm := NewFederationManager(server, serverName, edPrivKey, cert, discovery)
			server.federation = fm

			if err := fm.Start(); err != nil {
				log.Printf("Federation failed to start: %v (continuing without federation)", err)
			} else {
				log.Printf("Federation enabled, discovery URL: %s", discURL)
				defer fm.Stop()
			}
		}
	}

	log.Printf("IRC server listening on %s (TLS)", *addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		client := newClient(conn, server)
		go client.writeLoop()
		go client.readLoop()
	}
}
