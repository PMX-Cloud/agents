package main

import "testing"

func TestDeriveEnrollURLPreservesTransportSecurity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "secure websocket",
			in:   "wss://api.pmxcloud.example/ws/agent/core",
			want: "https://api.pmxcloud.example/agents/enroll",
		},
		{
			name: "private lan websocket",
			in:   "ws://192.168.100.174:8080/ws/agent",
			want: "http://192.168.100.174:8080/agents/enroll",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := deriveEnrollURL(tt.in); got != tt.want {
				t.Fatalf("deriveEnrollURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
