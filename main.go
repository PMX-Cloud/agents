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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/AraaRashek/pmx-cloud/agent/commands"
	"github.com/AraaRashek/pmx-cloud/agent/config"
	"github.com/AraaRashek/pmx-cloud/agent/wgtunnel"
	"github.com/AraaRashek/pmx-cloud/agent/wsclient"
)

const (
	DefaultConfigPath = "/etc/pmx-cloud/agent.conf"
	DefaultDataDir    = "/var/lib/pmx-cloud"
)

var (
	Version   = "0.1.0"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type Agent struct {
	config           *config.Config
	wsClient         *wsclient.Client
	wgManager        *wgtunnel.Manager
	commands         *commands.Dispatcher
	ctx              context.Context
	cancel           context.CancelFunc
	machineId        string
	wgPubkey         string
	sendEnvelopeHook func(messageType string, payload interface{}, correlationID string) error
}

type agentEnvelope struct {
	Version       string          `json:"version"`
	Type          string          `json:"type"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	Timestamp     int64           `json:"timestamp"`
	CorrelationID string          `json:"correlationId,omitempty"`
}

func main() {
	var (
		configPath = flag.String("config", DefaultConfigPath, "Path to configuration file")
		version    = flag.Bool("version", false, "Print version and exit")
		preflight  = flag.Bool("preflight", false, "Validate config and local identity files, then exit")
		setup      = flag.Bool("setup", false, "Run interactive setup")
	)
	flag.Parse()

	if *version {
		fmt.Printf("pmx-cloud-agent version %s commit %s built %s\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	if *preflight {
		if err := runPreflight(*configPath); err != nil {
			log.Fatalf("Preflight failed: %v", err)
		}
		log.Println("Preflight passed")
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
		commands:  commands.NewDispatcher(commands.ShellRunner{Timeout: 30 * time.Minute}),
	}

	// Create WebSocket client
	wsClient, err := wsclient.New(wsclient.Config{
		ServerURL:         cfg.ServerURL,
		Token:             cfg.Token,
		MachineId:         machineId,
		WireguardPubkey:   wgPubkey,
		AgentVersion:      Version,
		ReconnectInterval: 5 * time.Second,
		HeartbeatInterval: 30 * time.Second,
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
		DataDir:       cfg.DataDir,
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
	if err := a.sendRegistration(); err != nil {
		log.Printf("Failed to send agent registration: %v", err)
	}
}

func (a *Agent) handleDisconnect() {
	log.Println("Disconnected from pmx-Cloud backend")

	// When disconnected, we might want to keep the WireGuard tunnel up
	// for a grace period to avoid disrupting user traffic
}

func (a *Agent) handleMessage(msg []byte) {
	var message agentEnvelope

	if err := json.Unmarshal(msg, &message); err != nil {
		log.Printf("Failed to parse message: %v", err)
		return
	}

	if message.Version != wsclient.ProtocolVersion {
		log.Printf("Unsupported agent protocol version from server: %s", message.Version)
		return
	}

	switch message.Type {
	case "cloud.hello":
		log.Println("Backend is awaiting agent registration")
	case "cloud.registered":
		a.handleRegistered(message.Payload)
	case "cloud.heartbeat.ack":
		a.handleHeartbeatAck(message.Payload)
	case "cloud.ip.assignment":
		a.handleIpAssignment(message.Payload)
	case "cloud.ip.release":
		a.handleIpRelease()
	case "cloud.update":
		a.handleUpdate(message.Payload)
	case "cloud.error":
		a.handleCloudError(message.Payload)
	case "cloud.job.request":
		a.handleCommandRequest(message)
	default:
		if a.commands != nil && a.commands.Supports(message.Type) {
			a.handleCommandRequest(message)
			return
		}
		log.Printf("Unknown message type: %s", message.Type)
	}
}

func (a *Agent) sendRegistration() error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	capabilities := append([]string{"wireguard-relay", "node-management"}, commands.SupportedCommands()...)

	return a.sendEnvelope("agent.register", struct {
		Hostname           string   `json:"hostname"`
		ProxmoxVersion     string   `json:"proxmoxVersion,omitempty"`
		AgentVersion       string   `json:"agentVersion"`
		Capabilities       []string `json:"capabilities"`
		MachineID          string   `json:"machineId"`
		WireguardPublicKey string   `json:"wireguardPublicKey"`
	}{
		Hostname:           hostname,
		AgentVersion:       Version,
		Capabilities:       capabilities,
		MachineID:          a.machineId,
		WireguardPublicKey: a.wgPubkey,
	})
}

func (a *Agent) sendEnvelope(messageType string, payload interface{}) error {
	return a.sendEnvelopeWithCorrelation(messageType, payload, "")
}

func (a *Agent) sendEnvelopeWithCorrelation(messageType string, payload interface{}, correlationID string) error {
	if a.sendEnvelopeHook != nil {
		return a.sendEnvelopeHook(messageType, payload, correlationID)
	}

	envelope := wsclient.Envelope{
		Version:       wsclient.ProtocolVersion,
		Type:          messageType,
		Payload:       payload,
		Timestamp:     time.Now().UnixMilli(),
		CorrelationID: correlationID,
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	return a.wsClient.Send(data)
}

func (a *Agent) handleCommandRequest(message agentEnvelope) {
	command, payload, err := resolveCommandRequest(message)
	if err != nil {
		log.Printf("Invalid command request: %v", err)
		if sendErr := a.sendEnvelopeWithCorrelation("agent.error", map[string]string{
			"message": err.Error(),
		}, message.CorrelationID); sendErr != nil {
			log.Printf("Failed to send command error response: %v", sendErr)
		}
		return
	}

	log.Printf("Executing agent command %s", command)
	result := a.commands.DispatchWithObserver(a.ctx, command, payload, func(step commands.StepResult, stepIndex int, stepCount int) {
		progress := map[string]interface{}{
			"command":    command,
			"step":       step,
			"stepIndex":  stepIndex,
			"stepCount":  stepCount,
			"streamType": "step",
		}
		if err := a.sendEnvelopeWithCorrelation("agent.command.output", progress, message.CorrelationID); err != nil {
			log.Printf("Failed to stream command output: %v", err)
		}
	})
	if err := a.sendEnvelopeWithCorrelation("agent.response", result, message.CorrelationID); err != nil {
		log.Printf("Failed to send command response: %v", err)
	}
}

func resolveCommandRequest(message agentEnvelope) (string, json.RawMessage, error) {
	if message.Type != "cloud.job.request" {
		return message.Type, message.Payload, nil
	}

	var request struct {
		Command string          `json:"command"`
		JobType string          `json:"jobType"`
		Params  json.RawMessage `json:"params"`
	}

	if err := json.Unmarshal(message.Payload, &request); err != nil {
		return "", nil, fmt.Errorf("failed to parse job request: %w", err)
	}

	command := request.Command
	if command == "" {
		command = request.JobType
	}
	if command == "" {
		return "", nil, fmt.Errorf("cloud.job.request missing command or jobType")
	}

	payload := request.Params
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}

	return command, payload, nil
}

func (a *Agent) handleRegistered(data json.RawMessage) {
	var registered struct {
		ConnectionID        string `json:"connectionId"`
		HeartbeatIntervalMs int64  `json:"heartbeatIntervalMs"`
	}

	if err := json.Unmarshal(data, &registered); err != nil {
		log.Printf("Failed to parse registration acknowledgement: %v", err)
		return
	}

	log.Printf("Agent registered with connection ID %s", registered.ConnectionID)
}

func (a *Agent) handleHeartbeatAck(data json.RawMessage) {
	var ack struct {
		Active       *bool `json:"active,omitempty"`
		IpAssignment *struct {
			AssignedIp    string `json:"assignedIp"`
			RelayEndpoint string `json:"relayEndpoint"`
			RelayPubkey   string `json:"relayPubkey"`
			PeerWgIp      string `json:"peerWgIp"`
		} `json:"ipAssignment,omitempty"`
	}

	if err := json.Unmarshal(data, &ack); err != nil {
		log.Printf("Failed to parse heartbeat acknowledgement: %v", err)
		return
	}

	if ack.Active != nil && !*ack.Active {
		log.Println("License not active, stopping WireGuard tunnel")
		a.wgManager.Stop()
		return
	}

	if ack.IpAssignment != nil {
		a.configureWireGuard(ack.IpAssignment)
	} else {
		// No IP assignment, stop tunnel if running
		log.Println("Heartbeat acknowledged")
	}
}

func (a *Agent) handleCloudError(data json.RawMessage) {
	var errPayload struct {
		Message string `json:"message"`
	}

	if err := json.Unmarshal(data, &errPayload); err != nil {
		log.Printf("Backend reported an error")
		return
	}

	log.Printf("Backend reported an error: %s", errPayload.Message)
}

func (a *Agent) handleIpAssignment(data json.RawMessage) {
	var assignment struct {
		AssignedIp    string `json:"assignedIp"`
		RelayEndpoint string `json:"relayEndpoint"`
		RelayPubkey   string `json:"relayPubkey"`
		PeerWgIp      string `json:"peerWgIp"`
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
	AssignedIp    string `json:"assignedIp"`
	RelayEndpoint string `json:"relayEndpoint"`
	RelayPubkey   string `json:"relayPubkey"`
	PeerWgIp      string `json:"peerWgIp"`
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
			Endpoint:            assignment.RelayEndpoint,
			AllowedIPs:          "0.0.0.0/0",
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
	if err := installUpdate(a.ctx, update.Version, update.Url, update.Hash); err != nil {
		log.Printf("Self-update failed: %v", err)
		return
	}

	log.Printf("Self-update to version %s installed; restart the agent to run the new binary", update.Version)
}

func installUpdate(ctx context.Context, version string, rawURL string, expectedSHA256 string) error {
	if strings.TrimSpace(version) == "" {
		return errors.New("update version is required")
	}
	if strings.TrimSpace(rawURL) == "" {
		return errors.New("update URL is required")
	}
	if strings.TrimSpace(expectedSHA256) == "" {
		return errors.New("update SHA-256 hash is required")
	}

	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}
	executablePath, err = filepath.EvalSymlinks(executablePath)
	if err != nil {
		return fmt.Errorf("resolve executable symlink: %w", err)
	}

	executableInfo, err := os.Stat(executablePath)
	if err != nil {
		return fmt.Errorf("stat current executable: %w", err)
	}

	stagedPath := filepath.Join(
		filepath.Dir(executablePath),
		fmt.Sprintf(".%s.update-%d", filepath.Base(executablePath), time.Now().UnixNano()),
	)
	if err := downloadAndVerifyUpdate(ctx, rawURL, expectedSHA256, stagedPath); err != nil {
		_ = os.Remove(stagedPath)
		return err
	}
	if err := os.Chmod(stagedPath, executableInfo.Mode().Perm()); err != nil {
		_ = os.Remove(stagedPath)
		return fmt.Errorf("chmod staged update: %w", err)
	}

	backupPath := executablePath + ".bak"
	if err := os.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(stagedPath)
		return fmt.Errorf("remove previous backup: %w", err)
	}
	if err := os.Rename(executablePath, backupPath); err != nil {
		_ = os.Remove(stagedPath)
		return fmt.Errorf("backup current executable: %w", err)
	}
	if err := os.Rename(stagedPath, executablePath); err != nil {
		_ = os.Rename(backupPath, executablePath)
		_ = os.Remove(stagedPath)
		return fmt.Errorf("install staged update: %w", err)
	}

	return nil
}

func downloadAndVerifyUpdate(ctx context.Context, rawURL string, expectedSHA256 string, destinationPath string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse update URL: %w", err)
	}
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return fmt.Errorf("unsupported update URL scheme %q", parsedURL.Scheme)
	}

	expectedHash, err := normalizeSHA256Hash(expectedSHA256)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("create update request: %w", err)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("download update returned HTTP %d", response.StatusCode)
	}

	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create staged update: %w", err)
	}
	defer destination.Close()

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(destination, hasher), response.Body); err != nil {
		return fmt.Errorf("write staged update: %w", err)
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("update SHA-256 mismatch: expected %s got %s", expectedHash, actualHash)
	}

	return nil
}

func normalizeSHA256Hash(hash string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(hash))
	normalized = strings.TrimPrefix(normalized, "sha256:")
	if len(normalized) != sha256.Size*2 {
		return "", fmt.Errorf("update SHA-256 hash must be %d hex characters", sha256.Size*2)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("update SHA-256 hash is not valid hex: %w", err)
	}
	return normalized, nil
}

func getOrCreateMachineId(dataDir string) (string, error) {
	machineIdPath := filepath.Join(dataDir, "machine-id")

	// Try to read existing machine ID
	if data, err := os.ReadFile(machineIdPath); err == nil {
		machineID := strings.TrimSpace(string(data))
		if machineID == "" {
			return "", fmt.Errorf("stored machine ID is empty")
		}
		return machineID, nil
	}

	// Generate a stable machine ID from system machine-id + MAC address when
	// available. Non-systemd test or rescue environments still get a persisted
	// random identity instead of failing installation preflight.
	systemMachineId, err := getSystemMachineId()
	if err != nil {
		machineId, err := generateRandomMachineId()
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(machineIdPath, []byte(machineId), 0600); err != nil {
			return "", err
		}
		return machineId, nil
	}

	macAddress, err := getPrimaryMacAddress()
	if err != nil {
		machineId, err := generateRandomMachineId()
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(machineIdPath, []byte(machineId), 0600); err != nil {
			return "", err
		}
		return machineId, nil
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

func generateRandomMachineId() (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate random machine ID: %w", err)
	}
	return hex.EncodeToString(randomBytes), nil
}

func getSystemMachineId() (string, error) {
	return systemMachineIdFromSources(os.ReadFile, os.Hostname)
}

func systemMachineIdFromSources(
	readFile func(string) ([]byte, error),
	hostname func() (string, error),
) (string, error) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := readFile(path)
		if err != nil {
			continue
		}
		machineID := strings.TrimSpace(string(data))
		if machineID != "" {
			return machineID, nil
		}
	}

	host, err := hostname()
	if err == nil {
		host = strings.TrimSpace(host)
	}
	if host != "" {
		return "hostname:" + host, nil
	}

	return "", fmt.Errorf("could not find system machine-id or hostname")
}

func runPreflight(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	machineID, err := getOrCreateMachineId(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("prepare machine ID: %w", err)
	}
	if machineID == "" {
		return fmt.Errorf("machine ID is empty")
	}

	wgPubkey, err := wgtunnel.EnsureKeys(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("prepare WireGuard keys: %w", err)
	}
	if wgPubkey == "" {
		return fmt.Errorf("WireGuard public key is empty")
	}

	return nil
}

func getPrimaryMacAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	return primaryMacAddressFromInterfaces(interfaces)
}

func primaryMacAddressFromInterfaces(interfaces []net.Interface) (string, error) {
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		return iface.HardwareAddr.String(), nil
	}

	return "", fmt.Errorf("could not find active network interface with MAC address")
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
	fmt.Println("   server_url = wss://ws.pmxcloud.cloud/ws/agent")
	fmt.Println("   data_dir = /var/lib/pmx-cloud")
	fmt.Println()
	fmt.Println("3. Start the agent: pmx-cloud-agent")
	fmt.Println()

	return nil
}
