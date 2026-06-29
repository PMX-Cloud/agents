package envelope

import "errors"

// Sentinel errors returned by Envelope.Verify. Each maps to one of the six
// rejection paths mandated by architecture §3.4. Tests must cover every one.
var (
	ErrVersionUnsupported = errors.New("envelope: unsupported version")
	ErrExpired            = errors.New("envelope: expired")
	ErrTooLongLived       = errors.New("envelope: lifetime exceeds maximum (1h)")
	ErrAudienceMismatch   = errors.New("envelope: audience mismatch")
	ErrHostMismatch       = errors.New("envelope: host fingerprint mismatch")
	ErrBadSignature       = errors.New("envelope: bad signature")
	ErrReplay             = errors.New("envelope: replayed job ID")
)
