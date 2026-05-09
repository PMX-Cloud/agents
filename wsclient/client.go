/*
 * WebSocket Client
 *
 * Manages the WebSocket connection to the pmx-Cloud backend.
 * Handles reconnection, heartbeat, and message routing.
 */

package wsclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	ProtocolVersion = "pmx-agent-v1"
	MaxMessageBytes = 64 * 1024
)

type Envelope struct {
	Version       string      `json:"version"`
	Type          string      `json:"type"`
	Payload       interface{} `json:"payload,omitempty"`
	Timestamp     int64       `json:"timestamp"`
	CorrelationID string      `json:"correlationId,omitempty"`
}

type Config struct {
	ServerURL         string
	Token             string
	MachineId         string
	WireguardPubkey   string
	ReconnectInterval time.Duration
	HeartbeatInterval time.Duration
	OnMessage         func([]byte)
	OnConnect         func()
	OnDisconnect      func()
}

type Client struct {
	config    Config
	conn      *websocket.Conn
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	connected bool
	lastPong  time.Time
}

func New(cfg Config) (*Client, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("server URL is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("token is required")
	}
	if cfg.ReconnectInterval == 0 {
		cfg.ReconnectInterval = 5 * time.Second
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}

	return &Client{
		config: cfg,
	}, nil
}

func (c *Client) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Start connection manager
	go c.connectionManager()

	return nil
}

func (c *Client) Stop() {
	c.cancel()
	c.closeConnection()
}

func (c *Client) connectionManager() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if err := c.connect(); err != nil {
			log.Printf("Connection failed: %v", err)
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(c.config.ReconnectInterval):
				continue
			}
		}

		// Connection established, wait for disconnect
		c.waitForDisconnect()

		log.Printf("Disconnected, reconnecting in %v...", c.config.ReconnectInterval)
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(c.config.ReconnectInterval):
		}
	}
}

func (c *Client) connect() error {
	u, err := url.Parse(c.config.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	// Build headers with authentication
	headers := http.Header{
		"Authorization":            []string{"Bearer " + c.config.Token},
		"X-Machine-Id":             []string{c.config.MachineId},
		"X-WG-Pubkey":              []string{c.config.WireguardPubkey},
		"X-Agent-Version":          []string{"0.1.0"},
		"X-Agent-Protocol-Version": []string{ProtocolVersion},
	}

	log.Printf("Connecting to %s...", u.String())

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	conn.SetReadLimit(MaxMessageBytes)

	c.mu.Lock()
	c.conn = conn
	c.connected = true
	c.lastPong = time.Now()
	c.mu.Unlock()

	log.Println("WebSocket connected")

	if c.config.OnConnect != nil {
		c.config.OnConnect()
	}

	// Start goroutines for reading and heartbeat
	go c.readLoop()
	go c.heartbeatLoop()

	return nil
}

func (c *Client) closeConnection() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected = false
}

func (c *Client) waitForDisconnect() {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return
	}

	// Wait for connection to close
	for {
		c.mu.RLock()
		connected := c.connected
		c.mu.RUnlock()

		if !connected {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	if c.config.OnDisconnect != nil {
		c.config.OnDisconnect()
	}
}

func (c *Client) readLoop() {
	for {
		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()

		if conn == nil {
			return
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Read error: %v", err)
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			return
		}

		// Update last server-message time.
		c.mu.Lock()
		c.lastPong = time.Now()
		c.mu.Unlock()

		if c.config.OnMessage != nil {
			c.config.OnMessage(message)
		}
	}
}

func (c *Client) heartbeatLoop() {
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.sendHeartbeat(); err != nil {
				log.Printf("Failed to send heartbeat: %v", err)
			}
		}
	}
}

func (c *Client) sendHeartbeat() error {
	c.mu.RLock()
	conn := c.conn
	connected := c.connected
	c.mu.RUnlock()

	if !connected || conn == nil {
		return fmt.Errorf("not connected")
	}

	heartbeat := Envelope{
		Version:   ProtocolVersion,
		Type:      "agent.heartbeat",
		Timestamp: time.Now().UnixMilli(),
		Payload: struct {
			MachineID       string `json:"machineId"`
			WireguardStatus string `json:"wireguardStatus"`
		}{
			MachineID:       c.config.MachineId,
			WireguardStatus: "unknown", // Will be updated by agent
		},
	}

	data, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}

	return conn.WriteMessage(websocket.TextMessage, data)
}

func (c *Client) Send(message []byte) error {
	c.mu.RLock()
	conn := c.conn
	connected := c.connected
	c.mu.RUnlock()

	if !connected || conn == nil {
		return fmt.Errorf("not connected")
	}

	return conn.WriteMessage(websocket.TextMessage, message)
}

func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *Client) LastPong() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastPong
}
