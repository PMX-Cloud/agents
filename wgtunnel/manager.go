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
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
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
	config    Config
	device    *device.Device
	tunDevice wgtun.Device
	mu        sync.RWMutex
	running   bool
	stopChan  chan struct{}
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
	privateKeyBytes, err := os.ReadFile(tunnelCfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}
	privateKey, err := decodeWireGuardKey(string(privateKeyBytes))
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	localAddress, err := parseTunnelAddress(tunnelCfg.Address)
	if err != nil {
		return err
	}

	tunDevice, _, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddress},
		[]netip.Addr{},
		1420,
	)
	if err != nil {
		return fmt.Errorf("failed to create TUN: %w", err)
	}

	// Create WireGuard device
	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", m.config.InterfaceName))
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	// Configure device
	peerPublicKey, err := decodeWireGuardKey(tunnelCfg.Peer.PublicKey)
	if err != nil {
		tunDevice.Close()
		return fmt.Errorf("failed to decode peer public key: %w", err)
	}

	ipcRequest := fmt.Sprintf(`private_key=%s
listen_port=%d
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
allowed_ip=%s
`,
		hex.EncodeToString(privateKey),
		tunnelCfg.ListenPort,
		hex.EncodeToString(peerPublicKey),
		tunnelCfg.Peer.Endpoint,
		tunnelCfg.Peer.PersistentKeepalive,
		tunnelCfg.Peer.AllowedIPs,
	)

	if err := dev.IpcSet(ipcRequest); err != nil {
		tunDevice.Close()
		return fmt.Errorf("failed to configure device: %w", err)
	}

	if err := dev.Up(); err != nil {
		tunDevice.Close()
		return fmt.Errorf("failed to bring up device: %w", err)
	}

	m.device = dev
	m.tunDevice = tunDevice
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

	if m.tunDevice != nil {
		m.tunDevice.Close()
		m.tunDevice = nil
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

func parseTunnelAddress(value string) (netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), nil
	}

	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid tunnel address %q: %w", value, err)
	}

	return address, nil
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

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %w", err)
	}

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

func decodeWireGuardKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("wireguard key must decode to 32 bytes, got %d", len(key))
	}
	return key, nil
}
