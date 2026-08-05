package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Identity constants
const (
	IdentityContextURL = "https://ns.ircd.example/identity/v1"
	DIDContextURL      = "https://www.w3.org/ns/did/v1"

	// Proof types
	ProofTypeEd25519Sig2020 = "Ed25519Signature2020"

	// Challenge validity
	ChallengeValidity = 5 * time.Minute

	// DID method constants
	DIDMethodKey = "key"
	DIDMethodWeb = "web"

	// DID web fetch limits
	DIDWebFetchTimeout = 10 * time.Second
	DIDWebMaxSize      = 64 * 1024 // 64KB max for DID documents
)

// Multibase prefix for Ed25519 public keys (z = base58btc)
const MultibaseEd25519Prefix = "z"

// IdentityDocument represents a user's self-sovereign identity
type IdentityDocument struct {
	Context     interface{}          `json:"@context"`
	ID          string               `json:"id"` // DID
	AlsoKnownAs []string             `json:"alsoKnownAs,omitempty"`
	PublicKey   []PublicKeyEntry     `json:"publicKey,omitempty"`
	Service     []ServiceEndpoint    `json:"service,omitempty"`
	Credentials []json.RawMessage    `json:"verifiableCredential,omitempty"`
	Proof       *Proof               `json:"proof,omitempty"`
}

// PublicKeyEntry represents a public key in a DID document
type PublicKeyEntry struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

// ServiceEndpoint represents a service in a DID document
type ServiceEndpoint struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// Proof represents a cryptographic proof on an identity document
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	Challenge          string `json:"challenge"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

// DID represents a parsed Decentralized Identifier
type DID struct {
	Method     string // e.g., "key", "web"
	Identifier string // method-specific identifier
	Fragment   string // optional fragment (e.g., "#key-1")
	Base       string // DID without fragment (did:method:identifier)
}

// ParseDID parses a DID string into components
func ParseDID(did string) (*DID, error) {
	if !strings.HasPrefix(did, "did:") {
		return nil, errors.New("invalid DID: must start with 'did:'")
	}

	// Split off fragment
	fragment := ""
	if idx := strings.Index(did, "#"); idx != -1 {
		fragment = did[idx+1:]
		did = did[:idx]
	}

	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 {
		return nil, errors.New("invalid DID: must have format 'did:method:identifier'")
	}

	return &DID{
		Method:     parts[1],
		Identifier: parts[2],
		Fragment:   fragment,
		Base:       did,
	}, nil
}

// String returns the full DID string including fragment
func (d *DID) String() string {
	if d.Fragment != "" {
		return d.Base + "#" + d.Fragment
	}
	return d.Base
}

// WithoutFragment returns the DID without fragment
func (d *DID) WithoutFragment() string {
	return d.Base
}

// Base58Alphabet for decoding multibase z (base58btc)
const Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// DecodeBase58 decodes a base58btc string
func DecodeBase58(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty base58 input")
	}

	// Build index
	index := make(map[rune]int64)
	for i, c := range Base58Alphabet {
		index[c] = int64(i)
	}

	// Convert to big int
	var result []byte
	for _, c := range s {
		val, ok := index[c]
		if !ok {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}

		// Multiply result by 58 and add value
		carry := val
		for i := len(result) - 1; i >= 0; i-- {
			carry += int64(result[i]) * 58
			result[i] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			result = append([]byte{byte(carry & 0xff)}, result...)
			carry >>= 8
		}
	}

	// Handle leading zeros
	for _, c := range s {
		if c != '1' {
			break
		}
		result = append([]byte{0}, result...)
	}

	return result, nil
}

// DeriveEd25519FromDIDKey derives the Ed25519 public key from a did:key
// did:key format: did:key:z<multibase-encoded-multicodec-key>
// For Ed25519: multicodec prefix is 0xed01
func DeriveEd25519FromDIDKey(did *DID) (ed25519.PublicKey, error) {
	if did.Method != DIDMethodKey {
		return nil, fmt.Errorf("not a did:key: %s", did.Method)
	}

	identifier := did.Identifier
	if !strings.HasPrefix(identifier, "z") {
		return nil, errors.New("did:key identifier must start with 'z' (base58btc)")
	}

	// Decode base58btc (remove 'z' prefix)
	decoded, err := DecodeBase58(identifier[1:])
	if err != nil {
		return nil, fmt.Errorf("decode base58: %w", err)
	}

	// Check multicodec prefix for Ed25519 (0xed, 0x01)
	if len(decoded) < 2 {
		return nil, errors.New("decoded key too short")
	}

	// Ed25519 multicodec: 0xed 0x01 (varint encoded)
	// Raw key follows
	if decoded[0] == 0xed && decoded[1] == 0x01 {
		pubkey := decoded[2:]
		if len(pubkey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 key length: %d", len(pubkey))
		}
		return ed25519.PublicKey(pubkey), nil
	}

	return nil, fmt.Errorf("unsupported key type: multicodec 0x%x 0x%x", decoded[0], decoded[1])
}

// ResolveDIDDocument resolves a DID to its document
func ResolveDIDDocument(did *DID) (*IdentityDocument, error) {
	switch did.Method {
	case DIDMethodKey:
		return resolveDIDKey(did)
	case DIDMethodWeb:
		return resolveDIDWeb(did)
	default:
		return nil, fmt.Errorf("unsupported DID method: %s", did.Method)
	}
}

// resolveDIDKey creates a synthetic DID document for did:key
func resolveDIDKey(did *DID) (*IdentityDocument, error) {
	_, err := DeriveEd25519FromDIDKey(did)
	if err != nil {
		return nil, err
	}

	keyID := did.Base + "#key-1"

	return &IdentityDocument{
		Context: []string{DIDContextURL},
		ID:      did.Base,
		PublicKey: []PublicKeyEntry{
			{
				ID:                 keyID,
				Type:               "Ed25519VerificationKey2020",
				Controller:         did.Base,
				PublicKeyMultibase: did.Identifier,
			},
		},
	}, nil
}

// resolveDIDWeb fetches the DID document from the web
func resolveDIDWeb(did *DID) (*IdentityDocument, error) {
	// did:web:example.com -> https://example.com/.well-known/did.json
	// did:web:example.com:path:to -> https://example.com/path/to/did.json
	host := did.Identifier
	path := "/.well-known/did.json"

	// Handle path components (: becomes /)
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
		path = "/" + strings.Join(parts[1:], "/") + "/did.json"
	}

	// URL-decode the host (% encoding)
	host = strings.ReplaceAll(host, "%3A", ":")

	url := "https://" + host + path

	// Use client with explicit timeout to prevent hanging indefinitely
	client := &http.Client{Timeout: DIDWebFetchTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch did:web document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:web document fetch failed: %d", resp.StatusCode)
	}

	// Limit response size to prevent memory exhaustion
	body, err := io.ReadAll(io.LimitReader(resp.Body, DIDWebMaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read did:web document: %w", err)
	}
	if len(body) > DIDWebMaxSize {
		return nil, fmt.Errorf("did:web document too large (max %d bytes)", DIDWebMaxSize)
	}

	var doc IdentityDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse did:web document: %w", err)
	}

	return &doc, nil
}

// Challenge represents an identity challenge
type Challenge struct {
	Nick      string
	Server    string
	Timestamp int64
	Raw       string
}

// GenerateChallenge creates a new identity challenge
func GenerateChallenge(nick, server string) *Challenge {
	ts := time.Now().UnixNano()
	return &Challenge{
		Nick:      nick,
		Server:    server,
		Timestamp: ts,
		Raw:       fmt.Sprintf("irc:%s@%s:%d", nick, server, ts),
	}
}

// ParseChallenge parses a challenge string
// Format: irc:<nick>@<server>:<timestamp>
func ParseChallenge(s string) (*Challenge, error) {
	if !strings.HasPrefix(s, "irc:") {
		return nil, errors.New("challenge must start with 'irc:'")
	}

	rest := s[4:]

	// Find the last colon (timestamp separator)
	lastColon := strings.LastIndex(rest, ":")
	if lastColon == -1 {
		return nil, errors.New("invalid challenge format: missing timestamp")
	}

	tsStr := rest[lastColon+1:]
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}

	// Split nick@server
	nickServer := rest[:lastColon]
	atIdx := strings.Index(nickServer, "@")
	if atIdx == -1 {
		return nil, errors.New("invalid challenge format: missing @")
	}

	return &Challenge{
		Nick:      nickServer[:atIdx],
		Server:    nickServer[atIdx+1:],
		Timestamp: ts,
		Raw:       s,
	}, nil
}

// IsValid checks if the challenge is still valid (not expired)
func (c *Challenge) IsValid() bool {
	challengeTime := time.Unix(0, c.Timestamp)
	return time.Since(challengeTime) < ChallengeValidity
}

// Matches checks if the challenge matches expected nick and server
func (c *Challenge) Matches(nick, server string) bool {
	return strings.EqualFold(c.Nick, nick) && strings.EqualFold(c.Server, server)
}

// VerifyIdentityProof verifies an identity document's proof
func VerifyIdentityProof(doc *IdentityDocument, expectedNick, expectedServer string) error {
	if doc.Proof == nil {
		return errors.New("verify identity: document has no proof")
	}

	// Parse and validate challenge
	challenge, err := ParseChallenge(doc.Proof.Challenge)
	if err != nil {
		return fmt.Errorf("invalid challenge: %w", err)
	}

	if !challenge.IsValid() {
		return errors.New("verify identity: challenge expired")
	}

	if !challenge.Matches(expectedNick, expectedServer) {
		return errors.New("verify identity: challenge does not match nick/server")
	}

	// Parse DID from document
	did, err := ParseDID(doc.ID)
	if err != nil {
		return fmt.Errorf("invalid DID: %w", err)
	}

	// Get public key based on DID method
	var pubkey ed25519.PublicKey
	switch did.Method {
	case DIDMethodKey:
		pubkey, err = DeriveEd25519FromDIDKey(did)
		if err != nil {
			return fmt.Errorf("derive key from did:key: %w", err)
		}
	case DIDMethodWeb:
		// For did:web, we need to resolve the document and get the key
		pubkey, err = resolveVerificationMethod(doc, doc.Proof.VerificationMethod)
		if err != nil {
			return fmt.Errorf("resolve verification method: %w", err)
		}
	default:
		return fmt.Errorf("unsupported DID method: %s", did.Method)
	}

	// Verify signature
	if doc.Proof.Type != ProofTypeEd25519Sig2020 {
		return fmt.Errorf("unsupported proof type: %s", doc.Proof.Type)
	}

	// Decode signature
	sig, err := decodeProofValue(doc.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Build signing input per W3C Data Integrity spec for Ed25519Signature2020:
	// signingInput = hash(canonicalize(proof_options)) || hash(canonicalize(document))
	signingInput, err := dataIntegritySigningInput(doc)
	if err != nil {
		return fmt.Errorf("compute signing input: %w", err)
	}

	if !ed25519.Verify(pubkey, signingInput, sig) {
		return errors.New("verify identity: signature verification failed")
	}

	return nil
}

// resolveVerificationMethod gets the public key for a verification method
func resolveVerificationMethod(doc *IdentityDocument, method string) (ed25519.PublicKey, error) {
	// Parse verification method DID
	vmDID, err := ParseDID(method)
	if err != nil {
		return nil, err
	}

	// If it's a did:key, derive directly
	if vmDID.Method == DIDMethodKey {
		return DeriveEd25519FromDIDKey(vmDID)
	}

	// Otherwise look in document's publicKey array
	for _, pk := range doc.PublicKey {
		if pk.ID == method {
			if pk.PublicKeyMultibase == "" {
				return nil, errors.New("public key entry missing publicKeyMultibase")
			}

			// Parse multibase key
			if !strings.HasPrefix(pk.PublicKeyMultibase, "z") {
				return nil, errors.New("only base58btc (z) multibase supported")
			}

			decoded, err := DecodeBase58(pk.PublicKeyMultibase[1:])
			if err != nil {
				return nil, err
			}

			// Check for multicodec prefix
			if len(decoded) >= 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
				decoded = decoded[2:]
			}

			if len(decoded) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid key length: %d", len(decoded))
			}

			return ed25519.PublicKey(decoded), nil
		}
	}

	return nil, fmt.Errorf("verification method not found: %s", method)
}

// dataIntegritySigningInput computes the signing input per W3C Data Integrity spec.
// For Ed25519Signature2020: signingInput = hash(canonicalize(proof_options)) || hash(canonicalize(document))
// where proof_options is the proof without proofValue, and document is the doc without proof.
func dataIntegritySigningInput(doc *IdentityDocument) ([]byte, error) {
	if doc.Proof == nil {
		return nil, errors.New("document has no proof")
	}

	// Create proof options (proof without proofValue)
	proofOptions := &Proof{
		Type:               doc.Proof.Type,
		Created:            doc.Proof.Created,
		VerificationMethod: doc.Proof.VerificationMethod,
		Challenge:          doc.Proof.Challenge,
		ProofPurpose:       doc.Proof.ProofPurpose,
		// ProofValue intentionally omitted
	}

	proofOptionsJSON, err := CanonicalJSON(proofOptions)
	if err != nil {
		return nil, fmt.Errorf("canonical proof options: %w", err)
	}

	// Create document without proof
	docCopy := *doc
	docCopy.Proof = nil

	docJSON, err := CanonicalJSON(&docCopy)
	if err != nil {
		return nil, fmt.Errorf("canonical document: %w", err)
	}

	// Hash both and concatenate
	proofHash := sha256.Sum256(proofOptionsJSON)
	docHash := sha256.Sum256(docJSON)

	signingInput := make([]byte, 64)
	copy(signingInput[:32], proofHash[:])
	copy(signingInput[32:], docHash[:])

	return signingInput, nil
}

// decodeProofValue decodes the proof value (multibase or base64)
func decodeProofValue(value string) ([]byte, error) {
	// Check for multibase prefix
	if strings.HasPrefix(value, "z") {
		return DecodeBase58(value[1:])
	}

	// Try base64
	return base64.StdEncoding.DecodeString(value)
}

// CreateIdentityProof creates a signed identity document
func CreateIdentityProof(did string, challenge string, privKey ed25519.PrivateKey) (*IdentityDocument, error) {
	doc := &IdentityDocument{
		Context: []string{DIDContextURL, IdentityContextURL},
		ID:      did,
	}

	// Construct proof options (without proofValue) per W3C Data Integrity spec
	doc.Proof = &Proof{
		Type:               ProofTypeEd25519Sig2020,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: did + "#key-1",
		Challenge:          challenge,
		ProofPurpose:       "authentication",
		ProofValue:         "", // Will be set after signing
	}

	// Compute signing input per W3C Data Integrity spec:
	// signingInput = hash(canonicalize(proof_options)) || hash(canonicalize(document))
	signingInput, err := dataIntegritySigningInput(doc)
	if err != nil {
		return nil, fmt.Errorf("compute signing input: %w", err)
	}

	sig := ed25519.Sign(privKey, signingInput)
	doc.Proof.ProofValue = "z" + EncodeBase58(sig)

	return doc, nil
}

// EncodeBase58 encodes bytes to base58btc
func EncodeBase58(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Count leading zeros
	zeros := 0
	for _, b := range data {
		if b != 0 {
			break
		}
		zeros++
	}

	// Convert to base58
	size := len(data)*138/100 + 1
	buf := make([]byte, size)
	high := size - 1

	for _, b := range data {
		carry := int(b)
		for j := size - 1; j > high || carry != 0; j-- {
			carry += 256 * int(buf[j])
			buf[j] = byte(carry % 58)
			carry /= 58
			if j <= high {
				high = j - 1
			}
		}
	}

	// Skip leading zeros in output
	for high < size-1 && buf[high+1] == 0 {
		high++
	}

	// Build result
	var result strings.Builder
	for i := 0; i < zeros; i++ {
		result.WriteByte('1')
	}
	for i := high + 1; i < size; i++ {
		result.WriteByte(Base58Alphabet[buf[i]])
	}

	return result.String()
}

// CreateDIDKey creates a did:key from an Ed25519 public key
func CreateDIDKey(pubkey ed25519.PublicKey) string {
	// Prepend multicodec prefix for Ed25519 (0xed, 0x01)
	data := append([]byte{0xed, 0x01}, pubkey...)
	// Encode as base58btc with 'z' prefix
	return "did:key:z" + EncodeBase58(data)
}
