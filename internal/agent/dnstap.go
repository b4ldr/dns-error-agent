package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func runDNSTap(cfg Config, srv *Server, metricsServer *http.Server, sigch <-chan os.Signal) error {
	listener, cleanup, err := listenDNSTap(srv.dnstapNet, strings.TrimSpace(cfg.DNSTapAddress))
	if err != nil {
		stopMetricsServer(metricsServer)
		return err
	}
	defer cleanup()

	srv.logger.Printf("rfc9567 agent listening dnstap network=%s address=%s agent=%s", srv.dnstapNet, cfg.DNSTapAddress, srv.agentDomain)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveDNSTap(ctx, listener, cfg.DNSTapTimeout, srv)
	}()

	<-sigch
	cancel()
	_ = listener.Close()
	wg.Wait()
	stopMetricsServer(metricsServer)
	return nil
}

func listenDNSTap(network, address string) (net.Listener, func(), error) {
	cleanup := func() {}
	if network == DNSTapNetworkUnix {
		if err := os.Remove(address); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, cleanup, err
		}
		cleanup = func() {
			_ = os.Remove(address)
		}
	}

	listener, err := net.Listen(network, address)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}

	wrappedCleanup := func() {
		_ = listener.Close()
		cleanup()
	}

	return listener, wrappedCleanup, nil
}

func serveDNSTap(ctx context.Context, listener net.Listener, timeout time.Duration, srv *Server) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			srv.logger.Printf("dnstap accept failed: %v", err)
			continue
		}

		srv.logAt(2, "accepted dnstap connection remote=%s", conn.RemoteAddr())
		go func(c net.Conn) {
			defer c.Close()
			readDNSTapConn(c, timeout, srv)
		}(conn)
	}
}

func readDNSTapConn(conn net.Conn, timeout time.Duration, srv *Server) {
	input, err := dnstap.NewFrameStreamInputTimeout(conn, true, timeout)
	if err != nil {
		srv.logger.Printf("dnstap open input failed remote=%s err=%v", conn.RemoteAddr(), err)
		return
	}

	frames := make(chan []byte, 32)
	go input.ReadInto(frames)
	for frame := range frames {
		srv.processDNSTapFrame(frame)
	}

	srv.logAt(2, "closed dnstap connection remote=%s", conn.RemoteAddr())
}

func (s *Server) processDNSTapFrame(frame []byte) {
	var tap dnstap.Dnstap
	if err := proto.Unmarshal(frame, &tap); err != nil {
		s.logAt(1, "failed to decode dnstap frame: %v", err)
		s.metrics.observeReportEvent("malformed_query")
		return
	}

	if tap.Type == nil || *tap.Type != dnstap.Dnstap_MESSAGE || tap.Message == nil {
		s.logAt(3, "ignoring non-message dnstap frame")
		return
	}

	if tap.Message.Type == nil || !strings.HasSuffix(tap.Message.Type.String(), "QUERY") {
		s.logAt(3, "ignoring non-query dnstap message type=%v", tap.Message.Type)
		return
	}

	if len(tap.Message.QueryMessage) == 0 {
		s.logAt(1, "dropping malformed dnstap query: missing query payload")
		s.metrics.observeReportEvent("malformed_query")
		return
	}

	var msg dns.Msg
	if err := msg.Unpack(tap.Message.QueryMessage); err != nil {
		s.logAt(1, "dropping malformed dnstap query payload: %v", err)
		s.metrics.observeReportEvent("malformed_query")
		return
	}

	s.processReportMessage(&msg, dnstapTransport(tap.Message), dnstapRemoteAddr(tap.Message))
}

func dnstapTransport(msg *dnstap.Message) string {
	if msg == nil || msg.SocketProtocol == nil {
		return "dnstap"
	}
	transport := strings.ToLower(strings.TrimSpace(msg.SocketProtocol.String()))
	if transport == "" {
		return "dnstap"
	}
	return transport
}

func dnstapRemoteAddr(msg *dnstap.Message) net.Addr {
	if msg == nil {
		return nil
	}

	host := net.IP(msg.QueryAddress)
	port := int(msg.GetQueryPort())
	transport := dnstapTransport(msg)

	switch transport {
	case "tcp":
		return &net.TCPAddr{IP: host, Port: port}
	case "udp":
		return &net.UDPAddr{IP: host, Port: port}
	default:
		if host == nil {
			return staticAddr{value: fmt.Sprintf("%s:0", transport), network: "dnstap"}
		}
		return staticAddr{value: net.JoinHostPort(host.String(), fmt.Sprintf("%d", port)), network: transport}
	}
}

type staticAddr struct {
	value   string
	network string
}

func (a staticAddr) Network() string { return a.network }
func (a staticAddr) String() string  { return a.value }
