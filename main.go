/*
 * pmx-Cloud Agent
 *
 * A lightweight Go binary that runs on user's Proxmox hosts.
 * Connects to pmx-Cloud backend via WebSocket and manages WireGuard tunnels
 * for public IP relay service.
 *
 * Features:
 * - WebSocket connection with automatic reconnection
 * - WireGuard tunnel management (userspace implementation)
 * - Machine fingerprinting for license validation
 * - Self-update capability
 * - Proxmox API proxying
 */

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AraaRashek/pmx-cloud/agent/config"
	"github.com/AraaRashek/pmx-cloud/agent/wgtunnel"
	"github.com/AraaRashek/pmx-cloud/agent/wsclient"
)

const (
	Version           = "0.1.0"
	DefaultConfigPath = "/etc/pmx-cloud/agent.conf"
	DefaultDataDir    = "/var/lib/pmx-cloud"
)

type Agent struct {
	config      *config.Config
	wsClient    *wsclient.Client
	wgManager   *wgtunnel.Manager
	ctx         context.Context
	cancel      context.CancelFunc
	machineId   string
	wgPubkey    string
}

func main() {
	var (
		configPath = flag.String("config", DefaultConfigPath, "Path to configuration file")
		version    = flag.Bool("version", false, "Print version and exit")
		setup      = flag.Bool("setup", false, "Run interactive setup")
	)
	flag.Parse()

	if *version {
		fmt.Printf("pmx-cloud-agent version %s\n", Version)
		os.Exit(0)
	}

	if *setup {
		if err := runSetup(); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create and start agent
	agent, err := NewAgent(cfg)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	if err := agent.Run(); err != nil {
		log.Fatalf("Agent error: %v", err)
	}
}

func NewAgent(cfg *config.Config) (*Agent, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Ensure data directory exists
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Generate or load machine ID
	machineId, err := getOrCreateMachineId(cfg.DataDir)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get machine ID: %w", err)
	}

	// Generate or load WireGuard keys
	wgPubkey, err := wgtunnel.EnsureKeys(cfg.DataDir)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to ensure WireGuard keys: %w", err)
	}

	agent := &Agent{
		config:    cfg,
		ctx:       ctx,
		cancel:    cancel,
		machineId: machineId,
		wgPubkey:  wgPubkey,
	}

	// Create WebSocket client
	wsClient, err := wsclient.New(wsclient.Config{
		ServerURL:         cfg.ServerURL,
		Token:             cfg.Token,
		MachineId:         machineId,
		WireguardPubkey:   wgPubkey,
		ReconnectInterval: 5 * time.Second,
		HeartbeatInterval: 60 * time.Second,
		OnMessage:         agent.handleMessage,
		OnConnect:         agent.handleConnect,
		OnDisconnect:      agent.handleDisconnect,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create WebSocket client: %w", err)
	}
	agent.wsClient = wsClient

	// Create WireGuard manager
	wgManager, err := wgtunnel.New(wgtunnel.Config{
		InterfaceName: "wg-pmx",
		DataDir:     cfg.DataDir,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create WireGuard manager: %w", err)
	}
	agent.wgManager = wgManager

	return agent, nil
}

func (a *Agent) Run() error {
	log.Printf("pmx-cloud-agent %s starting...", Version)
	log.Printf("Machine ID: %s", a.machineId)
	log.Printf("WireGuard Pubkey: %s...", a.wgPubkey[:20])

	// Start WebSocket client
	if err := a.wsClient.Start(a.ctx); err != nil {
		return fmt.Errorf("failed to start WebSocket client: %w", err)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Printf("Received signal %s, shutting down...", sig)
	case <-a.ctx.Done():
		log.Println("Context cancelled, shutting down...")
	}

	return a.Shutdown()
}

func (a *Agent) Shutdown() error {
	a.cancel()

	// Stop WireGuard tunnel
	if a.wgManager != nil {
		if err := a.wgManager.Stop(); err != nil {
			log.Printf("Error stopping WireGuard: %v", err)
		}
	}

	// Stop WebSocket client
	if a.wsClient != nil {
		a.wsClient.Stop()
	}

	log.Println("Agent shutdown complete")
	return nil
}

func (a *Agent) handleConnect() {
	log.Println("Connected to pmx-Cloud backend")
}

func (a *Agent) handleDisconnect() {
	log.Println("Disconnected from pmx-Cloud backend")
	
	// When disconnected, we might want to keep the WireGuard tunnel up
	// for a grace period to avoid disrupting user traffic
}

func (a *Agent) handleMessage(msg []byte) {
	var message struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data,omitempty"`
	}

	if err := json.Unmarshal(msg, &message); err != nil {
		log.Printf("Failed to parse message: %v", err)
		return
	}

	switch message.Type {
	case "pong":
		a.handlePong(message.Data)
	case "ip_assignment":
		a.handleIpAssignment(message.Data)
	case "ip_release":
		a.handleIpRelease()
	case "update":
		a.handleUpdate(message.Data)
	default:
		log.Printf("Unknown message type: %s", message.Type)
	}
}

func (a *Agent) handlePong(data json.RawMessage) {
	var pong struct {
		Active        bool `json:"active"`
		IpAssignment  *struct {
			AssignedIp     string `json:"assigned_ip"`
			RelayEndpoint  string `json:"relay_endpoint"`
			RelayPubkey    string `json:"relay_pubkey"`
			PeerWgIp       string `json:"peer_wg_ip"`
		} `json:"ip_assignment,omitempty"`
	}

	if err := json.Unmarshal(data, &pong); err != nil {
		log.Printf("Failed to parse pong: %v", err)
		return
	}

	if !pong.Active {
		log.Println("License not active, stopping WireGuard tunnel")
		a.wgManager.Stop()
		return
	}

	if pong.IpAssignment != nil {
		a.configureWireGuard(pong.IpAssignment)
	} else {
		// No IP assignment, stop tunnel if running
		a.wgManager.Stop()
	}
}

func (a *Agent) handleIpAssignment(data json.RawMessage) {
	var assignment struct {
		AssignedIp     string `json:"assigned_ip"`
		RelayEndpoint  string `json:"relay_endpoint"`
		RelayPubkey    string `json:"relay_pubkey"`
		PeerWgIp       string `json:"peer_wg_ip"`
	}

	if err := json.Unmarshal(data, &assignment); err != nil {
		log.Printf("Failed to parse IP assignment: %v", err)
		return
	}

	a.configureWireGuard(&assignment)
}

func (a *Agent) handleIpRelease() {
	log.Println("Received IP release command")
	if err := a.wgManager.Stop(); err != nil {
		log.Printf("Error stopping WireGuard: %v", err)
	}
}

func (a *Agent) configureWireGuard(assignment *struct {
	AssignedIp     string `json:"assigned_ip"`
	RelayEndpoint  string `json:"relay_endpoint"`
	RelayPubkey    string `json:"relay_pubkey"`
	PeerWgIp       string `json:"peer_wg_ip"`
}) {
	log.Printf("Configuring WireGuard tunnel:")
	log.Printf("  Assigned IP: %s", assignment.AssignedIp)
	log.Printf("  Relay: %s", assignment.RelayEndpoint)
	log.Printf("  Peer WG IP: %s", assignment.PeerWgIp)

	config := wgtunnel.TunnelConfig{
		PrivateKeyPath: filepath.Join(a.config.DataDir, "wg-privatekey"),
		Address:        assignment.PeerWgIp + "/32",
		ListenPort:     0, // Client doesn't listen
		Peer: wgtunnel.PeerConfig{
			PublicKey:           assignment.RelayPubkey,
			Endpoint:          assignment.RelayEndpoint,
			AllowedIPs:        "0.0.0.0/0",
			PersistentKeepalive: 25,
		},
	}

	if err := a.wgManager.Start(config); err != nil {
		log.Printf("Failed to start WireGuard tunnel: %v", err)
		return
	}

	log.Println("WireGuard tunnel started successfully")
}

func (a *Agent) handleUpdate(data json.RawMessage) {
	var update struct {
		Version string `json:"version"`
		Url     string `json:"url"`
		Hash    string `json:"hash"`
	}

	if err := json.Unmarshal(data, &update); err != nil {
		log.Printf("Failed to parse update message: %v", err)
		return
	}

	log.Printf("Update available: version %s", update.Version)
	// TODO: Implement self-update
}

func getOrCreateMachineId(dataDir string) (string, error) {
	machineIdPath := filepath.Join(dataDir, "machine-id")

	// Try to read existing machine ID
	if data, err := os.ReadFile(machineIdPath); err == nil {
		return string(data), nil
	}

	// Generate new machine ID from system machine-id + MAC address
	systemMachineId, err := getSystemMachineId()
	if err != nil {
		return "", err
	}

	macAddress, err := getPrimaryMacAddress()
	if err != nil {
		return "", err
	}

	// Combine and hash
	hash := sha256.Sum256([]byte(systemMachineId + macAddress))
	machineId := hex.EncodeToString(hash[:])

	// Save machine ID
	if err := os.WriteFile(machineIdPath, []byte(machineId), 0600); err != nil {
		return "", err
	}

	return machineId, nil
}

func getSystemMachineId() (string, error) {
	// Try systemd machine-id
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		return string(data), nil
	}
	
	// Fallback to /var/lib/dbus/machine-id
	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		return string(data), nil
	}

	return "", fmt.Errorf("could not find system machine-id")
}

func getPrimaryMacAddress() (string, error) {
	// This is a simplified version - in production, use proper network interface detection
	// For now, return a placeholder that will be combined with machine-id
	return "00:00:00:00:00:00", nil
}

func runSetup() error {
	fmt.Println("pmx-Cloud Agent Setup")
	fmt.Println("=====================")
	fmt.Println()
	fmt.Println("This will guide you through setting up the pmx-Cloud agent.")
	fmt.Println()

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup must be run as root")
	}

	// Create directories
	if err := os.MkdirAll("/etc/pmx-cloud", 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.MkdirAll("/var/lib/pmx-cloud", 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	fmt.Println("Directories created successfully.")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("1. Get your license token from the pmx-Cloud dashboard")
	fmt.Println("2. Create /etc/pmx-cloud/agent.conf with your configuration:")
	fmt.Println()
	fmt.Println("   token = YOUR_LICENSE_TOKEN")
	fmt.Println("   server_url = wss://ws.pmxcloud.cloud")
	fmt.Println("   data_dir = /var/lib/pmx-cloud")
	fmt.Println()
	fmt.Println("3. Start the agent: pmx-cloud-agent")
	fmt.Println()

	return nil
}
