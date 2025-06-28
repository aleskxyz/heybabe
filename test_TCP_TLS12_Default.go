package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

	// This is for systems that don't have a good set of roots. (update often)
	_ "golang.org/x/crypto/x509roots/fallback"
)

// test_TCP_TLS12_Default is a go crypto/tls connection using:
// TCP
// default cipher suites
// forced TLS1.2
// default elliptic curve preferences
func test_TCP_TLS12_Default(ctx context.Context, l *slog.Logger, addrPort netip.AddrPort, sni string) TestAttemptResult {
	counter, _, _, _ := runtime.Caller(0)
	l = l.With("test", strings.Split(runtime.FuncForPC(counter).Name(), ".")[1], "ip", addrPort.Addr().String())

	l.Debug("starting TCP TLS12 Default test", 
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

	l.Debug("configuring TLS connection")
	tlsConfig := tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
		CipherSuites:       nil,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CurvePreferences:   nil,
	}

	tlsConn := tls.Client(tcpConn, &tlsConfig)
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
