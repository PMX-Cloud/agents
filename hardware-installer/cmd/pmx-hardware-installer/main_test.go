package main

import "testing"

func TestClassifyReject(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want string
	}{
		{assertErr("bad signature"), "BAD_SIGNATURE"},
		{assertErr("audience mismatch"), "AUDIENCE_MISMATCH"},
		{assertErr("expired"), "EXPIRED"},
		{assertErr("replay"), "REPLAY"},
		{assertErr("other"), "VERIFY_FAILED"},
	}
	for _, tc := range cases {
		if got := classifyReject(tc.err); got != tc.want {
			t.Fatalf("classifyReject(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func assertErr(msg string) error { return &fixedErr{msg: msg} }

type fixedErr struct{ msg string }

func (e *fixedErr) Error() string { return e.msg }
