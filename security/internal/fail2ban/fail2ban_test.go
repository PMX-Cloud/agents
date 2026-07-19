package fail2ban

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/pmx-cloud/agents/security/internal/rootscope"
)

type mockRootRunner struct {
	results map[string]*rootscope.Result
	errors  map[string]error
	calls   []string
	args    map[string][]string
}

func (m *mockRootRunner) RunRoot(_ context.Context, _ string, name, _ string, args []string, hardening rootscope.Hardening) (*rootscope.Result, error) {
	m.calls = append(m.calls, name)
	if m.args == nil {
		m.args = map[string][]string{}
	}
	m.args[name] = append([]string(nil), args...)
	if hardening.AppArmorProfile != "pmx-security-fail2ban" {
		return nil, errors.New("missing fail2ban AppArmor scope")
	}
	return m.results[name], m.errors[name]
}

func TestStatusParsesRunningJails(t *testing.T) {
	runner := &mockRootRunner{results: map[string]*rootscope.Result{
		"fail2ban-loaded":       {Stdout: []byte("loaded\n")},
		"fail2ban-active":       {},
		"fail2ban-jail-proxmox": {Stdout: []byte("`- Actions\n   |- Currently banned: 3\n   |- Total banned: 8\n   `- Banned IP list: 203.0.113.8 invalid-entry 192.0.2.9\n")},
		"fail2ban-jail-ssh":     {Stdout: []byte("`- Actions\n   |- Currently banned: 1\n   |- Total banned: 4\n   `- Banned IP list: 198.51.100.7\n")},
	}, errors: map[string]error{}}

	status, err := Status(context.Background(), "job1", runner)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Installed || !status.Running {
		t.Fatalf("expected installed/running status, got %+v", status)
	}
	if status.Jails["proxmox"].Total != 8 || status.Jails["proxmox"].Banned != 2 {
		t.Fatalf("unexpected proxmox status: %+v", status.Jails["proxmox"])
	}
	wantIPs := []string{"192.0.2.9", "203.0.113.8"}
	if !reflect.DeepEqual(status.Jails["proxmox"].BannedIPs, wantIPs) {
		t.Fatalf("banned IPs = %v, want %v", status.Jails["proxmox"].BannedIPs, wantIPs)
	}
}

func TestStatusReportsMissingServiceWithoutFabrication(t *testing.T) {
	runner := &mockRootRunner{
		results: map[string]*rootscope.Result{"fail2ban-loaded": {Stdout: []byte("not-found\n")}},
		errors:  map[string]error{},
	}
	status, err := Status(context.Background(), "job1", runner)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Installed || status.Running || len(runner.calls) != 1 {
		t.Fatalf("unexpected missing-service status: %+v calls=%v", status, runner.calls)
	}
}

func TestStatusPropagatesLoadStateExecutionFailure(t *testing.T) {
	runner := &mockRootRunner{
		results: map[string]*rootscope.Result{"fail2ban-loaded": {ExitCode: 1, Stderr: []byte("access denied")}},
		errors:  map[string]error{"fail2ban-loaded": errors.New("exit status 1")},
	}
	if _, err := Status(context.Background(), "job1", runner); err == nil {
		t.Fatal("expected load-state execution failure")
	}
}

func TestInstallStartsServiceBeforeReadingStatus(t *testing.T) {
	runner := &mockRootRunner{results: map[string]*rootscope.Result{
		"fail2ban-install": {},
		"fail2ban-loaded":  {Stdout: []byte("loaded\n")},
		"fail2ban-active":  {},
	}, errors: map[string]error{}}
	status, err := Install(context.Background(), "job1", runner)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !status.Installed || !status.Running || runner.calls[0] != "fail2ban-install" {
		t.Fatalf("unexpected install result: %+v calls=%v", status, runner.calls)
	}
	if !reflect.DeepEqual(runner.args["fail2ban-install"], []string{"start", "fail2ban.service"}) {
		t.Fatalf("install args = %v", runner.args["fail2ban-install"])
	}
}

func TestUnbanValidatesJailAndIP(t *testing.T) {
	runner := &mockRootRunner{results: map[string]*rootscope.Result{}, errors: map[string]error{}}
	if _, err := Unban(context.Background(), "job1", UnbanParams{Jail: "other", IP: "192.0.2.1"}, runner); err == nil {
		t.Fatal("expected invalid jail error")
	}
	if _, err := Unban(context.Background(), "job1", UnbanParams{Jail: "ssh", IP: "not-an-ip"}, runner); err == nil {
		t.Fatal("expected invalid IP error")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("validation must happen before execution: %v", runner.calls)
	}
}

func TestBannedFlattensBothJails(t *testing.T) {
	runner := &mockRootRunner{results: map[string]*rootscope.Result{
		"fail2ban-loaded":       {Stdout: []byte("loaded\n")},
		"fail2ban-active":       {},
		"fail2ban-jail-proxmox": {Stdout: []byte("Banned IP list: 203.0.113.8\n")},
		"fail2ban-jail-ssh":     {Stdout: []byte("Banned IP list: 198.51.100.7\n")},
	}, errors: map[string]error{}}
	result, err := Banned(context.Background(), "job1", runner)
	if err != nil {
		t.Fatalf("Banned: %v", err)
	}
	if result.Total != 2 || result.BannedIPs[0].Jail != "proxmox" || result.BannedIPs[1].Jail != "ssh" {
		t.Fatalf("unexpected banned result: %+v", result)
	}
}
