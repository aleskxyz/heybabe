package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

	// This is for systems that don't have a good set of roots. (update often)
	_ "golang.org/x/crypto/x509roots/fallback"

	"github.com/markpash/heybabe/bepass/tlsfrag"
	tls "github.com/refraction-networking/utls"
)

// test_TCP_TLS13_UTLS_ChromeAuto_bepass_fragment is a uTLS connection using:
// TCP
// default cipher suites
// forced TLS1.3
// default elliptic curve preferences
// utls.HelloChrome_Auto
// And the bepass fragmenting TCP connection!
func test_TCP_TLS13_UTLS_ChromeAuto_bepass_fragment(ctx context.Context, l *slog.Logger, addrPort netip.AddrPort, sni string) TestAttemptResult {
	counter, _, _, _ := runtime.Caller(0)
	l = l.With("test", strings.Split(runtime.FuncForPC(counter).Name(), ".")[1], "ip", addrPort.Addr().String())

	l.Debug("starting TCP TLS13 UTLS ChromeAuto bepass fragment test", 
		"target", addrPort.String(),
		"sni", sni)

	res := TestAttemptResult{}

	// Initiate TCP connection
	l.Debug("initiating TCP connection")
	tcpDialer := net.Dialer{
		Timeout:       5 * time.Second,
		LocalAddr:     nil,
		FallbackDelay: -1, // disable happy-eyeballs
		KeepAlive:     15, // default
		Resolver:      &net.Resolver{PreferGo: true},
	}
	tcpDialer.SetMultipathTCP(false)

	t0 := time.Now()
	tcpConn, err := tcpDialer.DialContext(ctx, "tcp", addrPort.String())
	if err != nil {
		l.Error("failed to establish TCP connection", "error", err)
		res.err = err
		return res
	}
	defer tcpConn.Close()
	res.TransportEstablishDuration = time.Since(t0)
	l.Debug("TCP connection established", "duration", res.TransportEstablishDuration)

	// bepass frag settings
	bsl := [2]int{2000, 2000} // ChunksLengthBeforeSni
	sl := [2]int{1, 2}        // SniChunksLength
	asl := [2]int{1, 2}       // ChunksLengthAfterSni
	delay := [2]int{10, 20}   // DelayBetweenChunks

	l.Debug("creating TLS fragmentation adapter", "bsl", bsl, "sl", sl, "asl", asl, "delay", delay)
	tcpTlsFragConn := tlsfrag.New(tcpConn, bsl, sl, asl, delay, l)

	l.Debug("configuring TLS connection")
	tlsConfig := tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
		CipherSuites:       nil,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   nil,
	}

	tlsConn := tls.UClient(tcpTlsFragConn, &tlsConfig, tls.HelloChrome_Auto)
	defer tlsConn.Close()

	// Explicitly run the handshake
	l.Debug("starting TLS handshake")
	t0 = time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		l.Error("TLS handshake failed", "error", err)
		res.err = err
		return res
	}
	res.TLSHandshakeDuration = time.Since(t0)
	l.Debug("TLS handshake completed", "duration", res.TLSHandshakeDuration)

	tlsState := tlsConn.ConnectionState()
	l.Info("test completed successfully", 
		"handshake_complete", tlsState.HandshakeComplete,
		"transport_duration", res.TransportEstablishDuration,
		"tls_duration", res.TLSHandshakeDuration)
	return res
}
