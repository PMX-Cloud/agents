/*
Package wsclient implements the outbound-only WebSocket client used by every
PMX-Cloud fleet agent (architecture §P2, §5).

Key design constraints (house rules):
  - Agents NEVER open a listening socket. All connections are agent→backend.
  - Inbound WS frames that are not valid signed envelopes are rejected and logged.
  - Backpressure is applied by not reading the next WS frame while the handler is busy.
*/
package wsclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pmx-cloud/agents/shared/envelope"
)

const (
	// ProtocolVersion is the JSON wrapper protocol used for registration/heartbeat.
	ProtocolVersion = "pmx-agent-v1"

	// DefaultHeartbeatInterval is 15 s as mandated by architecture §5.
	DefaultHeartbeatInterval = 15 * time.Second

	// DefaultHeartbeatTimeout is 3× the heartbeat interval.
	DefaultHeartbeatTimeout = 45 * time.Second

	// BackoffMin is the initial reconnect wait.
	BackoffMin = 5 * time.Second

	// BackoffMax caps the exponential backoff.
	BackoffMax = 60 * time.Second

	// MaxMessageBytes caps inbound WS frame size.
	MaxMessageBytes = 1 << 20 // 1 MiB
)

// Handler is implemented by each domain agent to process inbound commands.
type Handler interface {
	// OnEnvelope is called exactly once for each valid signed envelope. Return
	// (result, nil) on success or (nil, err) to send an error response.
	OnEnvelope(ctx context.Context, env *envelope.Envelope) (result []byte, err error)

	// OnConnect is called once after the WebSocket handshake succeeds.
	OnConnect(ctx context.Context, c *Client) error
}

// Config holds all parameters required to start the WS client.
type Config struct {
	// BackendURL must be a wss:// URL.
	BackendURL string

	// AgentClass identifies this agent type (e.g. "pmx-network").
	AgentClass string

	// AuthToken is an optional backend credential presented during WS handshake.
	AuthToken string

	// mTLS paths.
	CertPath string
	KeyPath  string

	// KeySet for envelope signature verification.
	KeySet *envelope.KeySet

	// ReplayCache for replay protection.
	ReplayCache *envelope.ReplayCache

	// HostFingerprint is the SHA-256 hex of the host identity.
	HostFingerprint string

	// HypervisorType is the host-agnostic backend the agent operates against,
	// reported to the backend at agent.register so the right HypervisorProvider
	// is selected for the node. One of "proxmox", "libvirt", "generic-linux".
	// Empty means the agent does not own a hypervisor surface (e.g. pmx-network
	// running on a Proxmox host alongside pmx-hypervisor) — leave the backend's
	// existing assignment alone.
	HypervisorType string

	// BaseOS describes the host operating system (e.g. "proxmox-ve-8",
	// "debian-12", "ubuntu-24.04"). Only set by the supervising agent that
	// reports hypervisor capabilities.
	BaseOS string

	// Capabilities is the structured discovery payload (matches the
	// agents/hypervisor/internal/provider Capabilities struct). Persisted onto
	// nodes.capabilities so the UI knows which tabs to light up.
	Capabilities map[string]any

	// HeartbeatInterval defaults to DefaultHeartbeatInterval.
	HeartbeatInterval time.Duration

	// HeartbeatTimeout defaults to DefaultHeartbeatTimeout.
	HeartbeatTimeout time.Duration

	// Handler processes inbound signed envelopes.
	Handler Handler

	// Logger defaults to slog.Default().
	Logger *slog.Logger

	// AuditChainHead is a func that returns the current audit log chain head hex.
	// If nil, the heartbeat omits the auditChainHead field.
	AuditChainHead func() string

	// AllowInsecureWS permits ws:// URLs (test-only; production always requires wss://).
	AllowInsecureWS bool
}

// Client manages the WebSocket connection lifecycle for one agent.
// It is outbound-only: the agent dials the backend; the backend never dials back.
type Client struct {
	cfg     Config
	log     *slog.Logger
	mu      sync.RWMutex
	conn    *websocket.Conn
	writeMu sync.Mutex
}

// New validates cfg and returns a ready-to-Run Client.
func New(cfg Config) (*Client, error) {
	if cfg.BackendURL == "" {
		return nil, fmt.Errorf("wsclient: BackendURL is required")
	}
	if !cfg.AllowInsecureWS && (len(cfg.BackendURL) < 5 || (strings.HasPrefix(cfg.BackendURL, "wss://") == false && strings.HasPrefix(cfg.BackendURL, "ws://") == false)) {
		return nil, fmt.Errorf("wsclient: BackendURL must start with wss:// or ws://")
	}
	if cfg.AgentClass == "" {
		return nil, fmt.Errorf("wsclient: AgentClass is required")
	}
	if cfg.KeySet == nil {
		return nil, fmt.Errorf("wsclient: KeySet is required")
	}
	if cfg.ReplayCache == nil {
		return nil, fmt.Errorf("wsclient: ReplayCache is required")
	}
	if cfg.Handler == nil {
		return nil, fmt.Errorf("wsclient: Handler is required")
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if cfg.HeartbeatTimeout == 0 {
		cfg.HeartbeatTimeout = DefaultHeartbeatTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{cfg: cfg, log: logger}, nil
}

// Run connects to the backend and blocks until ctx is cancelled.
// It reconnects with exponential backoff on any disconnect.
func (c *Client) Run(ctx context.Context) error {
	backoff := BackoffMin
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		connErr := c.runOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.log.Warn("wsclient: disconnected, will reconnect",
			"err", connErr,
			"backoff", backoff,
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		// Exponential backoff with cap.
		backoff *= 2
		if backoff > BackoffMax {
			backoff = BackoffMax
		}
	}
}

// SendRaw sends a raw byte payload over the current connection. Used by agents
// to send job results back to the backend.
func (c *Client) SendRaw(data []byte) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return fmt.Errorf("wsclient: not connected")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// runOnce dials, runs the read/heartbeat loops, and returns when the
// connection drops or ctx is cancelled. Resets backoff on success.
func (c *Client) runOnce(ctx context.Context) error {
	conn, err := c.dial()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	c.log.Info("wsclient: connected", "url", c.cfg.BackendURL, "agent", c.cfg.AgentClass)

	if err := c.cfg.Handler.OnConnect(ctx, c); err != nil {
		return fmt.Errorf("OnConnect: %w", err)
	}
	if err := c.sendRegistration(conn); err != nil {
		return fmt.Errorf("register: %w", err)
	}

	missedBeats := 0
	beatTicker := time.NewTicker(c.cfg.HeartbeatInterval)
	defer beatTicker.Stop()

	// Liveness via WS ping/pong with a read deadline. A half-open TCP
	// connection (peer sent FIN, our writes still buffer locally and appear to
	// succeed) cannot be detected by checking only that the app-level heartbeat
	// write returned nil — it always does until the OS gives up minutes later.
	// Instead we set a read deadline that every inbound frame (and every pong)
	// extends; if the backend stops answering pings the read deadline fires,
	// ReadMessage errors, and we reconnect. The backend's `ws` server answers
	// ping frames with pongs automatically.
	_ = conn.SetReadDeadline(time.Now().Add(c.cfg.HeartbeatTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(c.cfg.HeartbeatTimeout))
	})

	readErrCh := make(chan error, 1)
	go func() { readErrCh <- c.readLoop(ctx, conn) }()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-readErrCh:
			return err

		case <-beatTicker.C:
			// A control ping shares the write path with app frames, so a dead
			// peer surfaces here as a write error too — but the authoritative
			// signal is the read deadline the pong (or any frame) resets.
			if err := conn.WriteControl(
				websocket.PingMessage,
				nil,
				time.Now().Add(10*time.Second),
			); err != nil {
				return fmt.Errorf("ping write failed: %w", err)
			}
			if err := c.sendHeartbeat(conn); err != nil {
				missedBeats++
				c.log.Warn("wsclient: heartbeat failed", "miss", missedBeats, "err", err)
				if missedBeats >= 3 {
					return fmt.Errorf("heartbeat send failed %d times: %w", missedBeats, err)
				}
			} else {
				missedBeats = 0
			}
		}
	}
}

// dial establishes the mTLS WebSocket connection.
func (c *Client) dial() (*websocket.Conn, error) {
	var tlsCfg *tls.Config
	if c.cfg.CertPath != "" && c.cfg.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(c.cfg.CertPath, c.cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("wsclient: load mTLS cert: %w", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 10 * time.Second,
	}

	url := buildBackendURL(c.cfg.BackendURL, c.cfg.AgentClass)
	headers := http.Header{
		"X-Agent-Class": []string{c.cfg.AgentClass},
	}
	if token := strings.TrimSpace(c.cfg.AuthToken); token != "" {
		headers.Set("Authorization", "Bearer "+token)
		headers.Set("X-License-Key", token)
	}

	conn, _, err := dialer.Dial(url, headers)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(MaxMessageBytes)
	return conn, nil
}

func buildBackendURL(backendURL string, agentClass string) string {
	trimmed := strings.TrimRight(backendURL, "/")
	if strings.HasSuffix(trimmed, "/"+agentClass) {
		return trimmed
	}
	if shortClass := strings.TrimPrefix(agentClass, "pmx-"); shortClass != agentClass {
		if strings.HasSuffix(trimmed, "/"+shortClass) {
			return trimmed
		}
	}
	return trimmed + "/" + agentClass
}

// readLoop reads WS frames, verifies each as a signed envelope, and dispatches
// to the handler. Returns on any read error or context cancellation.
func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		// Any inbound frame proves the connection is alive — extend the read
		// deadline so a busy link never trips the liveness timeout.
		_ = conn.SetReadDeadline(time.Now().Add(c.cfg.HeartbeatTimeout))
		// The gateway sends JSON control frames (e.g. cloud.hello,
		// cloud.registered) as text messages. Only binary frames can carry signed
		// CBOR job envelopes, so ignore non-binary traffic like the Rust wsclient.
		if messageType != websocket.BinaryMessage {
			continue
		}

		env, err := envelope.Unmarshal(msg)
		if err != nil {
			c.log.Warn("wsclient: reject: not a valid envelope",
				"PMX_REJECT_REASON", "unmarshal_error",
				"err", err,
			)
			continue
		}

		if err := env.Verify(c.cfg.KeySet, c.cfg.AgentClass, c.cfg.HostFingerprint, c.cfg.ReplayCache); err != nil {
			c.log.Warn("wsclient: reject: envelope verify failed",
				"PMX_REJECT_REASON", err.Error(),
				"PMX_JOB_ID", env.JobID,
			)
			continue
		}

		// Backpressure: do NOT read the next frame until the handler returns.
		result, handlerErr := c.cfg.Handler.OnEnvelope(ctx, env)
		if handlerErr != nil {
			c.log.Error("wsclient: handler error",
				"PMX_JOB_ID", env.JobID,
				"PMX_COMMAND", env.Command,
				"err", handlerErr,
			)
		}
		if result != nil {
			// Wrap the handler result with the job id so the gateway can
			// correlate it even when several signed requests are in flight on
			// this connection — bare payloads are only attributable when
			// exactly one request is pending, anything else gets dropped.
			if sendErr := c.SendRaw(wrapJobResult(env.JobID, result)); sendErr != nil {
				c.log.Error("wsclient: send result failed", "err", sendErr)
			}
		}
	}
}

// wrapJobResult envelopes a raw handler result as {type:"result", jobId,
// payload|error} for response correlation. The handler's bytes are passed
// through verbatim under "payload" when they are valid JSON; handler error
// bodies ({"error": "..."}) keep their error string at the top level so the
// gateway rejects the pending request instead of resolving it.
func wrapJobResult(jobID string, result []byte) []byte {
	var parsed any
	if err := json.Unmarshal(result, &parsed); err != nil {
		parsed = string(result)
	}

	wrapper := map[string]any{
		"type":  "result",
		"jobId": jobID,
	}
	if obj, ok := parsed.(map[string]any); ok {
		if errMsg, ok := obj["error"].(string); ok && errMsg != "" {
			wrapper["error"] = errMsg
		} else {
			wrapper["payload"] = parsed
		}
	} else {
		wrapper["payload"] = parsed
	}

	wrapped, err := json.Marshal(wrapper)
	if err != nil {
		return result
	}
	return wrapped
}

// sendHeartbeat sends the 15-second heartbeat frame (architecture §5).
func (c *Client) sendHeartbeat(conn *websocket.Conn) error {
	chainHead := ""
	if c.cfg.AuditChainHead != nil {
		chainHead = c.cfg.AuditChainHead()
	}
	payload, err := json.Marshal(map[string]any{
		"version":   ProtocolVersion,
		"type":      "agent.heartbeat",
		"timestamp": time.Now().UTC().UnixMilli(),
		"payload": map[string]any{
			"agentClass":     c.cfg.AgentClass,
			"auditChainHead": chainHead,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return conn.WriteMessage(websocket.TextMessage, payload)
}

func (c *Client) sendRegistration(conn *websocket.Conn) error {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	agentVersion := "unknown"

	registrationPayload := map[string]any{
		"hostname":        hostname,
		"agentVersion":    agentVersion,
		"agentClass":      c.cfg.AgentClass,
		"hostFingerprint": c.cfg.HostFingerprint,
		"capabilities":    []string{},
	}
	// Additive fields — backends that pre-date the node-first migration just
	// ignore unknown keys (no protocol version bump needed).
	if c.cfg.HypervisorType != "" {
		registrationPayload["hypervisorType"] = c.cfg.HypervisorType
	}
	if c.cfg.BaseOS != "" {
		registrationPayload["baseOs"] = c.cfg.BaseOS
	}
	if len(c.cfg.Capabilities) > 0 {
		registrationPayload["capabilitiesMap"] = c.cfg.Capabilities
	}

	payload, err := json.Marshal(map[string]any{
		"version":   ProtocolVersion,
		"type":      "agent.register",
		"timestamp": time.Now().UTC().UnixMilli(),
		"payload":   registrationPayload,
	})
	if err != nil {
		return fmt.Errorf("marshal register: %w", err)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return conn.WriteMessage(websocket.TextMessage, payload)
}
