package provider

import (
	"os/exec"
)

// Detect probes the host for available hypervisors and returns the highest-
// privilege backend present. Order:
//
//  1. Proxmox VE   (pveversion binary on PATH or /usr/bin/pveversion)
//  2. libvirt/KVM  (virsh binary on PATH or /usr/bin/virsh)
//  3. none         (plain Linux host)
//
// This is used by the --provider=auto startup flag in cmd/pmx-hypervisor/main.go
// so an operator can install pmx-hypervisor on either a Proxmox host or a
// plain Debian/Ubuntu host and have the right backend selected automatically.
func Detect() Kind {
	if hasBinary("pveversion", "/usr/bin/pveversion") {
		return KindProxmox
	}
	if hasBinary("virsh", "/usr/bin/virsh") {
		return KindLibvirt
	}
	return KindNone
}

func hasBinary(name string, fallbackPath string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	if fallbackPath == "" {
		return false
	}
	if _, err := exec.LookPath(fallbackPath); err == nil {
		return true
	}
	return false
}
