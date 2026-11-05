// Package funnel implements a TLS-preserving ingress using Tailscale PeerAPI.
package funnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

const maxConnections = 1024

type identity struct {
	NodeID     types.NodeID `json:"node_id"`
	MachineKey string       `json:"machine_key"`
}

// Server owns the shared listener and its managed tailnet identity. Control
// connections are handed to HTTP; application TLS is never terminated here.
type Server struct {
	listener      net.Listener
	control       chan net.Conn
	ctx           context.Context
	cancel        context.CancelFunc
	state         *state.State
	cfg           *types.Config
	node          *tsnet.Server
	ready         atomic.Bool
	mu            sync.Mutex
	connections   map[net.Conn]struct{}
	wg            sync.WaitGroup
	closeOnce     sync.Once
	closeErr      error
	nodeCloseOnce sync.Once
	nodeCloseErr  error
}

// New starts demultiplexing without touching identity storage. Control-plane
// availability never depends on that storage or on the embedded client.
func New(listener net.Listener, cfg *types.Config, st *state.State) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		listener: listener, control: make(chan net.Conn), ctx: ctx, cancel: cancel,
		state: st, cfg: cfg, connections: make(map[net.Conn]struct{}),
	}
	s.node = &tsnet.Server{
		Dir:      filepath.Join(cfg.DNSConfig.Funnel.StateDir, "tailscale"),
		Hostname: "headscale-funnel", ControlURL: cfg.ServerURL, Logf: logger.Discard,
	}
	s.wg.Go(s.accept)
	return s
}

// Start initializes Funnel after control HTTP is serving. Initialization
// failure closes only the embedded client; the shared listener keeps serving.
func (s *Server) Start(notify func()) {
	s.wg.Go(func() {
		ctx, cancel := context.WithTimeout(s.ctx, time.Minute)
		defer cancel()
		if err := s.up(ctx); err != nil {
			if s.ctx.Err() == nil {
				log.Error().Err(err).Msg("Funnel unavailable; Headscale and DERP continue serving; repair the cause and restart to enable Funnel")
				notify()
			}
			_ = s.closeNode()
			return
		}
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			return
		}
		s.ready.Store(true)
		s.state.SetFunnelAvailable(true)
		s.mu.Unlock()
		notify()
		log.Info().Msg("embedded funnel identity ready on the shared TLS listener")
	})
}

// up registers a tagged node once, then binds ingress authority to that exact
// persisted node and machine identity. A deleted node is not resurrected.
func (s *Server) up(ctx context.Context) error {
	if err := os.MkdirAll(s.cfg.DNSConfig.Funnel.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.cfg.DNSConfig.Funnel.StateDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(s.cfg.DNSConfig.Funnel.StateDir, "identity.json")
	var saved identity
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &saved); err != nil {
			return fmt.Errorf("read funnel identity: %w", err)
		}
		n, ok := s.state.GetNodeByID(saved.NodeID)
		if !ok || n.MachineKey().String() != saved.MachineKey || n.IsExpired() || !n.IsTagged() {
			return errors.New("managed funnel node was deleted, expired or replaced; restore its identity or explicitly reset dns.funnel.state_dir")
		}
		s.state.SetFunnelNode(saved.NodeID)
	} else if errors.Is(err, os.ErrNotExist) {
		// Refuse ambiguous crash recovery instead of minting another identity.
		if _, err := os.Stat(s.node.Dir); !errors.Is(err, os.ErrNotExist) {
			return errors.New("funnel identity metadata is missing but client state exists; restore identity.json or explicitly reset dns.funnel.state_dir")
		}
		expiry := time.Now().Add(5 * time.Minute)
		pak, err := s.state.CreatePreAuthKey(nil, false, false, &expiry, []string{"tag:headscale-funnel"})
		if err != nil {
			return fmt.Errorf("create funnel bootstrap key: %w", err)
		}
		defer s.state.RevokePreAuthKey(pak.ID)
		s.node.AuthKey = pak.Key
	} else {
		return err
	}

	status, err := s.node.Up(ctx)
	if err != nil {
		return fmt.Errorf("start funnel identity: %w", err)
	}
	var found types.NodeView
	for _, n := range s.state.ListNodes().All() {
		if n.NodeKey() == status.Self.PublicKey {
			found = n
			break
		}
	}
	if !found.Valid() || !found.IsTagged() {
		return errors.New("managed funnel identity not found in control state")
	}
	actual := identity{found.ID(), found.MachineKey().String()}
	if saved.NodeID != 0 && saved != actual {
		return errors.New("managed funnel identity changed unexpectedly")
	}
	if saved.NodeID == 0 {
		data, err := json.Marshal(actual)
		if err != nil {
			return err
		}
		if err := os.WriteFile(path+".tmp", data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return err
		}
	}
	s.state.SetFunnelNode(actual.NodeID)
	return nil
}

// Control is the listener to wrap in tls.NewListener for the existing HTTP server.
func (s *Server) Control() net.Listener { return controlListener{s} }

type controlListener struct{ s *Server }

func (l controlListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.s.control:
		return c, nil
	case <-l.s.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l controlListener) Addr() net.Addr { return l.s.listener.Addr() }
func (l controlListener) Close() error   { l.s.cancel(); return l.s.listener.Close() }

// Close tears down active public flows before the HTTP/map streams are stopped.
func (s *Server) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.close() })
	return s.closeErr
}

func (s *Server) close() error {
	s.cancel()
	_ = s.listener.Close()
	s.mu.Lock()
	s.ready.Store(false)
	s.state.SetFunnelAvailable(false)
	for c := range s.connections {
		_ = c.Close()
	}
	s.mu.Unlock()
	err := s.closeNode()
	s.wg.Wait()
	return err
}

func (s *Server) closeNode() error {
	s.nodeCloseOnce.Do(func() { s.nodeCloseErr = s.node.Close() })
	return s.nodeCloseErr
}

func (s *Server) accept() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if len(s.connections) >= maxConnections || s.ctx.Err() != nil {
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.connections[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Go(func() {
			defer func() { s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
			s.route(c)
		})
	}
}

var errHelloRead = errors.New("client hello read")

// helloConn records exactly the bytes crypto/tls consumed and suppresses TLS
// alerts: both successful and rejected probes must leave the wire untouched.
type helloConn struct {
	net.Conn
	data bytes.Buffer
}

func (c *helloConn) Read(p []byte) (int, error) {
	if c.data.Len() >= 65536 {
		return 0, errors.New("client hello too large")
	}
	p = p[:min(len(p), 65536-c.data.Len())]
	n, err := c.Conn.Read(p)
	_, _ = c.data.Write(p[:n])
	return n, err
}
func (c *helloConn) Write(p []byte) (int, error) { return len(p), nil }

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (s *Server) route(raw net.Conn) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	probe := &helloConn{Conn: raw}
	var host string
	err := tls.Server(probe, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		host = strings.ToLower(hello.ServerName)
		return nil, errHelloRead
	}}).HandshakeContext(s.ctx)
	if !errors.Is(err, errHelloRead) {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	c := &replayConn{raw, io.MultiReader(bytes.NewReader(probe.data.Bytes()), raw)}
	control, _ := url.Parse(s.cfg.ServerURL)
	if host == "" || host == strings.ToLower(control.Hostname()) {
		// Ownership passes to HTTP. Keep this goroutine (and the raw connection
		// in the shutdown registry) alive until HTTP closes it.
		done := make(chan struct{})
		tracked := &controlConn{Conn: c, done: done}
		select {
		case s.control <- tracked:
			select {
			case <-done:
			case <-s.ctx.Done():
			}
		case <-s.ctx.Done():
		}
		return
	}
	if !s.ready.Load() {
		return
	}
	target, ok := s.state.FunnelTarget(host)
	if !ok {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	stopRaw := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopRaw()
	// Revalidate active flows as policy, hostname and publication state change.
	watchDone := make(chan struct{})
	watchExited := make(chan struct{})
	defer func() { close(watchDone); <-watchExited }()
	go func() {
		defer close(watchExited)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				n, ok := s.state.FunnelTarget(host)
				if !ok || n.ID() != target.ID() {
					cancel()
					_ = raw.Close()
					return
				}
			case <-watchDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	upstream, err := s.ingress(ctx, target, host, raw.RemoteAddr().String())
	if err != nil {
		log.Debug().Err(err).Str(zf.FunnelTarget, host).Msg("funnel ingress rejected")
		return
	}
	defer upstream.Close()
	// Closing either side must unblock both copies, including on revocation.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close(); _ = upstream.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		n, err := io.Copy(upstream, c)
		log.Debug().Err(err).Int64(zf.FunnelBytes, n).Str(zf.FunnelTarget, host).Msg("funnel client stream ended")
		if cw, ok := upstream.Conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	}()
	n, err := io.Copy(raw, upstream)
	log.Debug().Err(err).Int64(zf.FunnelBytes, n).Str(zf.FunnelTarget, host).Msg("funnel target stream ended")
	_ = raw.Close()
	_ = upstream.Close()
	<-done
}

type controlConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *controlConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

func (s *Server) ingress(ctx context.Context, target types.NodeView, host, source string) (*replayConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	lc, err := s.node.LocalClient()
	if err != nil {
		return nil, err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	peer := status.Peer[target.NodeKey()]
	if peer == nil || len(peer.PeerAPIURL) == 0 {
		return nil, errors.New("target peer API not available")
	}
	endpoint, err := url.Parse(peer.PeerAPIURL[0])
	if err != nil || endpoint.Scheme != "http" {
		return nil, errors.New("invalid peer API URL")
	}
	log.Debug().Str(zf.FunnelEndpoint, endpoint.Host).Str(zf.FunnelTarget, host).Msg("funnel dialing peer API")
	c, err := s.node.Dial(ctx, "tcp", endpoint.Host)
	if err != nil {
		return nil, err
	}
	stopHandshake := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stopHandshake()
	log.Debug().Str(zf.FunnelTarget, host).Msg("funnel peer API connected")
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+endpoint.Host+"/v0/ingress", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Tailscale-Ingress-Src", source)
	req.Header.Set("Tailscale-Ingress-Target", net.JoinHostPort(host, s.state.FunnelPort()))
	if err := req.Write(c); err != nil {
		return nil, err
	}
	// PeerAPI is authenticated, but still bound its response before parsing it.
	limited := &io.LimitedReader{R: c, N: 16384}
	br := bufio.NewReader(limited)
	response, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	log.Debug().Int(zf.StatusCode, response.StatusCode).Str(zf.FunnelTarget, host).Msg("funnel peer API response")
	if response.StatusCode != http.StatusSwitchingProtocols {
		_ = response.Body.Close()
		return nil, fmt.Errorf("peer API ingress returned %d", response.StatusCode)
	}
	pending, err := br.Peek(br.Buffered())
	if err != nil {
		return nil, err
	}
	buffered := bytes.Clone(pending)
	_ = c.SetDeadline(time.Time{})
	ok = true
	return &replayConn{c, io.MultiReader(bytes.NewReader(buffered), c)}, nil
}
