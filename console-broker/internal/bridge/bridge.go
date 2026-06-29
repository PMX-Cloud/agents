// Package bridge pipes console bytes between local socket and backend WS.
package bridge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

type Options struct {
	RateLimitMbps int
}

type Metrics struct {
	BytesLocalToWS int64     `json:"bytes_local_to_ws"`
	BytesWSToLocal int64     `json:"bytes_ws_to_local"`
	FramesToWS     int64     `json:"frames_to_ws"`
	FramesFromWS   int64     `json:"frames_from_ws"`
	StartedAt      time.Time `json:"started_at"`
	EndedAt        time.Time `json:"ended_at"`
}

func DialBackend(ctx context.Context, backendWSURL, certPath, keyPath, sessionToken string) (*websocket.Conn, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("bridge: load mTLS cert: %w", err)
	}
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		},
		HandshakeTimeout: 10 * time.Second,
	}
	headers := http.Header{}
	headers.Set("X-Agent-Class", "pmx-console-broker")

	conn, _, err := dialer.DialContext(ctx, backendWSURL, headers)
	if err != nil {
		return nil, fmt.Errorf("bridge: ws dial %s failed: %w", backendWSURL, err)
	}
	conn.SetReadLimit(8 << 20) // 8 MiB max frame
	if err := conn.WriteMessage(websocket.TextMessage, []byte(sessionToken)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("bridge: session auth frame failed: %w", err)
	}
	return conn, nil
}

func Run(ctx context.Context, localConn net.Conn, wsConn *websocket.Conn, opts Options) (*Metrics, error) {
	if localConn == nil || wsConn == nil {
		return nil, fmt.Errorf("bridge: local and ws connections are required")
	}

	started := time.Now().UTC()
	metrics := &Metrics{StartedAt: started}

	limit := opts.RateLimitMbps
	if limit <= 0 {
		limit = 100
	}
	bytesPerSecond := rate.Limit(limit * 125000)
	localToWSLimiter := rate.NewLimiter(bytesPerSecond, 64*1024)
	wsToLocalLimiter := rate.NewLimiter(bytesPerSecond, 64*1024)

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = wsConn.Close()
			_ = localConn.Close()
		})
	}
	defer closeBoth()

	errCh := make(chan error, 2)
	go func() {
		errCh <- copyLocalToWS(ctx, localConn, wsConn, localToWSLimiter, metrics)
	}()
	go func() {
		errCh <- copyWSToLocal(ctx, wsConn, localConn, wsToLocalLimiter, metrics)
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			firstErr = ctx.Err()
			closeBoth()
		case err := <-errCh:
			if firstErr == nil && err != nil {
				firstErr = err
			}
			closeBoth()
		}
	}
	metrics.EndedAt = time.Now().UTC()

	if firstErr == nil {
		return metrics, nil
	}
	if errors.Is(firstErr, context.DeadlineExceeded) || errors.Is(firstErr, context.Canceled) {
		return metrics, nil
	}
	if errors.Is(firstErr, io.EOF) || websocket.IsCloseError(firstErr, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		return metrics, nil
	}
	if isClosedNetworkError(firstErr) {
		return metrics, nil
	}
	return metrics, firstErr
}

func copyLocalToWS(
	ctx context.Context,
	localConn net.Conn,
	wsConn *websocket.Conn,
	limiter *rate.Limiter,
	metrics *Metrics,
) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := localConn.Read(buf)
		if n > 0 {
			if waitErr := limiter.WaitN(ctx, n); waitErr != nil {
				return waitErr
			}
			if writeErr := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
				return writeErr
			}
			atomic.AddInt64(&metrics.BytesLocalToWS, int64(n))
			atomic.AddInt64(&metrics.FramesToWS, 1)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.EOF
			}
			return err
		}
	}
}

func copyWSToLocal(
	ctx context.Context,
	wsConn *websocket.Conn,
	localConn net.Conn,
	limiter *rate.Limiter,
	metrics *Metrics,
) error {
	for {
		messageType, payload, err := wsConn.ReadMessage()
		if err != nil {
			return err
		}
		if messageType != websocket.BinaryMessage {
			continue
		}
		if len(payload) == 0 {
			continue
		}
		if waitErr := limiter.WaitN(ctx, len(payload)); waitErr != nil {
			return waitErr
		}
		if _, err := localConn.Write(payload); err != nil {
			return err
		}
		atomic.AddInt64(&metrics.BytesWSToLocal, int64(len(payload)))
		atomic.AddInt64(&metrics.FramesFromWS, 1)
	}
}

func isClosedNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "use of closed network connection") || strings.Contains(msg, "broken pipe")
}
