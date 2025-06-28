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

	quic "github.com/refraction-networking/uquic"
	tls "github.com/refraction-networking/utls"
)

// test_QUIC_TLS13_UQUIC_Chrome_115_Default
func test_QUIC_TLS13_UQUIC_Chrome_115_Default(ctx context.Context, l *slog.Logger, addrPort netip.AddrPort, sni string) TestAttemptResult {
	counter, _, _, _ := runtime.Caller(0)
	l = l.With("test", strings.Split(runtime.FuncForPC(counter).Name(), ".")[1], "ip", addrPort.Addr().String())

	l.Debug("starting QUIC TLS13 UQUIC Chrome 115 Default test", 
		"target", addrPort.String(),
		"sni", sni)

	res := TestAttemptResult{}

	l.Debug("configuring TLS and QUIC connection")
	tlsConfig := tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
		CipherSuites:       nil,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   nil,
		NextProtos:         []string{"h3"},
	}

	quicConf := &quic.Config{}

	l.Debug("creating UDP socket for QUIC")
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		l.Error("failed to create UDP socket", "error", err)
		res.err = err
		return res
	}

	l.Debug("getting QUIC spec for Chrome 115")
	quicSpec, err := quic.QUICID2Spec(quic.QUICChrome_115)
	if err != nil {
		l.Error("failed to get QUIC spec", "error", err)
		res.err = err
		return res
	}

	ut := &quic.UTransport{
		Transport: &quic.Transport{Conn: udpConn},
		QUICSpec:  &quicSpec,
	}

	t0 := time.Now()
	l.Debug("dialing QUIC connection")
	quicConn, err := ut.Dial(ctx, net.UDPAddrFromAddrPort(addrPort), &tlsConfig, quicConf)
	if err != nil {
		l.Error("failed to establish QUIC connection", "error", err)
		res.err = err
		return res
	}
	defer quicConn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
	res.TransportEstablishDuration = time.Since(t0)
	l.Debug("QUIC connection established", "duration", res.TransportEstablishDuration)

	l.Info("test completed successfully", 
		"handshake_complete", quicConn.ConnectionState().TLS.HandshakeComplete,
		"transport_duration", res.TransportEstablishDuration)
	return res
}
