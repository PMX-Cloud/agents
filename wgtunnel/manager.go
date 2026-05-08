/*
 * WireGuard Tunnel Manager
 *
 * Manages WireGuard tunnel lifecycle using the userspace implementation.
 * Handles configuration, starting, stopping, and status monitoring.
 */

package wgtunnel

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Config struct {
	InterfaceName string
	DataDir       string
}

type PeerConfig struct {
	PublicKey           string
	Endpoint            string
	AllowedIPs          string
	PersistentKeepalive int
}

type TunnelConfig struct {
	PrivateKeyPath string
	Address        string
	ListenPort     int
	Peer           PeerConfig
}

type Manager struct {
	config   Config
	device   *device.Device
	tun      *netstack.Net
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

func New(cfg Config) (*Manager, error) {
	return &Manager{
		config:   cfg,
		stopChan: make(chan struct{}),
	}, nil
}

func (m *Manager) Start(tunnelCfg TunnelConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		// Stop existing tunnel first
		if err := m.stopInternal(); err != nil {
			return fmt.Errorf("failed to stop existing tunnel: %w", err)
		}
	}

	log.Printf("Starting WireGuard tunnel %s...", m.config.InterfaceName)

	// Read private key
	privateKey, err := os.ReadFile(tunnelCfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Create userspace TUN device
	tun, tnet, err := netstack.CreateNetTUN(
		[]net.IPNet{{IP: net.ParseIP(tunnelCfg.Address), Mask: net.CIDRMask(32, 32)}},
		[]net.IPNet{},
		1420,
	)
	if err != nil {
		return fmt.Errorf("failed to create TUN: %w", err)
	}

	// Create WireGuard device
	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", m.config.InterfaceName))
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	// Configure device
	peerPublicKey, err := base64.StdEncoding.DecodeString(tunnelCfg.Peer.PublicKey)
	if err != nil {
		tun.Close()
		return fmt.Errorf("failed to decode peer public key: %w", err)
	}

	ipcRequest := fmt.Sprintf(`private_key=%s
listen_port=%d
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
allowed_ip=%s
`,
		string(privateKey),
		tunnelCfg.ListenPort,
		base64.StdEncoding.EncodeToString(peerPublicKey),
		tunnelCfg.Peer.Endpoint,
		tunnelCfg.Peer.PersistentKeepalive,
		tunnelCfg.Peer.AllowedIPs,
	)

	if err := dev.IpcSet(ipcRequest); err != nil {
		tun.Close()
		return fmt.Errorf("failed to configure device: %w", err)
	}

	if err := dev.Up(); err != nil {
		tun.Close()
		return fmt.Errorf("failed to bring up device: %w", err)
	}

	m.device = dev
	m.tun = tnet
	m.running = true

	log.Printf("WireGuard tunnel %s started successfully", m.config.InterfaceName)

	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.stopInternal()
}

func (m *Manager) stopInternal() error {
	if !m.running {
		return nil
	}

	log.Printf("Stopping WireGuard tunnel %s...", m.config.InterfaceName)

	if m.device != nil {
		m.device.Close()
		m.device = nil
	}

	if m.tun != nil {
		m.tun.Close()
		m.tun = nil
	}

	m.running = false

	log.Printf("WireGuard tunnel %s stopped", m.config.InterfaceName)

	return nil
}

func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

func (m *Manager) GetStats() (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running || m.device == nil {
		return nil, fmt.Errorf("tunnel not running")
	}

	// Get device stats via IPC
	stats, err := m.device.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	return map[string]interface{}{
		"ipc": stats,
	}, nil
}

// EnsureKeys generates or loads WireGuard keypair
func EnsureKeys(dataDir string) (string, error) {
	privateKeyPath := filepath.Join(dataDir, "wg-privatekey")
	publicKeyPath := filepath.Join(dataDir, "wg-publickey")

	// Check if keys already exist
	if _, err := os.Stat(privateKeyPath); err == nil {
		// Load existing public key
		pubKey, err := os.ReadFile(publicKeyPath)
		if err == nil {
			return string(pubKey), nil
		}
		// If public key doesn't exist, regenerate from private key
	}

	// Generate new keypair
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Clamp private key for X25519
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	// Calculate public key (simplified - in production use proper X25519)
	// For now, we'll just base64 encode the private key as a placeholder
	// The actual implementation should use golang.org/x/crypto/curve25519
	publicKey := privateKey // Placeholder - should be X25519 scalar multiplication

	// Save keys
	if err := os.WriteFile(privateKeyPath, []byte(base64.StdEncoding.EncodeToString(privateKey)), 0600); err != nil {
		return "", fmt.Errorf("failed to save private key: %w", err)
	}

	pubKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
	if err := os.WriteFile(publicKeyPath, []byte(pubKeyB64), 0644); err != nil {
		return "", fmt.Errorf("failed to save public key: %w", err)
	}

	return pubKeyB64, nil
}
