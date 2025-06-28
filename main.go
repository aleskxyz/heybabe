package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/carlmjohnson/versioninfo"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

const appName = "heybabe"

var (
	version   = ""
	logLevels = []string{
		slog.LevelInfo.String(),
		slog.LevelDebug.String(),
		slog.LevelWarn.String(),
		slog.LevelError.String(),
	}
)

func main() {
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	l.Debug("starting heybabe application")
	
	fs := ff.NewFlagSet(appName)
	var (
		v4       = fs.BoolShort('4', "only resolve IPv4 (only works when IP is not set)")
		v6       = fs.BoolShort('6', "only resolve IPv6 (only works when IP is not set)")
		sni      = fs.StringLong("sni", "", "tls sni (if IP flag not provided, this SNI will be resolved by system DNS)")
		port     = fs.UintLong("port", 443, "tls port")
		ip       = fs.StringLong("ip", "", "manually provide IP (no DNS lookup)")
		repeat   = fs.UintLong("repeat", 1, "number of times to repeat each test")
		logLevel = fs.StringEnumLong("loglevel", fmt.Sprintf("specify a log level (valid values: %s)", logLevels), logLevels...)
		logJson  = fs.Bool('j', "json", "log in json format")
		verFlag  = fs.BoolLong("version", "displays version number")
	)

	l.Debug("parsing command line arguments")
	err := ff.Parse(fs, os.Args[1:])
	switch {
	case errors.Is(err, ff.ErrHelp):
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
		os.Exit(0)
	case err != nil:
		l.Error("failed to parse command line arguments", "error", err)
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *verFlag {
		if version == "" {
			version = versioninfo.Short()
		}
		fmt.Fprintf(os.Stderr, "%s\n", version)
		os.Exit(0)
	}

	l.Debug("configuring logger", "log_level", *logLevel, "log_json", *logJson)
	var lOpts *slog.HandlerOptions
	switch *logLevel {
	case slog.LevelDebug.String():
		lOpts = &slog.HandlerOptions{Level: slog.LevelDebug}
	case slog.LevelInfo.String():
		lOpts = &slog.HandlerOptions{Level: slog.LevelInfo}
	case slog.LevelWarn.String():
		lOpts = &slog.HandlerOptions{Level: slog.LevelWarn}
	case slog.LevelError.String():
		lOpts = &slog.HandlerOptions{Level: slog.LevelError}
	default:
		// Default to INFO level if no log level specified
		lOpts = &slog.HandlerOptions{Level: slog.LevelInfo}
	}

	var lHandler slog.Handler
	if *logJson {
		lHandler = slog.NewJSONHandler(os.Stdout, lOpts)
	} else {
		lHandler = slog.NewTextHandler(os.Stdout, lOpts)
	}

	l = slog.New(lHandler)
	l.Debug("logger configured successfully")

	// Make sure that port does not exceed 65535
	if *port > uint(^uint16(0)) {
		l.Error("invalid port number", "port", *port, "max_port", 65535)
		fatal(l, fmt.Errorf("invalid port %v", *port))
	}

	if *sni == "" {
		l.Error("SNI not specified")
		fatal(l, errors.New("must specify SNI"))
	}

	l.Debug("validating configuration", 
		"sni", *sni,
		"port", *port,
		"ip", *ip,
		"ipv4_only", *v4,
		"ipv6_only", *v6,
		"repeat", *repeat)

	addr := netip.IPv4Unspecified()
	if *ip != "" {
		if *v4 || *v6 {
			l.Error("cannot specify both IP and IPv4/IPv6 flags")
			fatal(l, errors.New("cannot set ip and -4 or -6"))
		}
		addr, err = netip.ParseAddr(*ip)
		if err != nil {
			l.Error("failed to parse IP address", "ip", *ip, "error", err)
			fatal(l, err)
		}
		l.Debug("using manual IP address", "ip", addr)
	} else if *v4 == *v6 {
		// Essentially doing XNOR to make sure that if they are both false
		// or both true, just set them both true.
		*v4, *v6 = true, true
		l.Debug("auto-detecting IPv4 and IPv6 addresses")
	}

	l.Debug("setting up signal handling")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		defer cancel()

		to := TestOptions{
			ResolveIPv4: *v4,
			ResolveIPv6: *v6,
			ManualIP:    addr.Unmap(),
			Port:        uint16(*port),
			SNI:         *sni,
			Repeat:      *repeat,
		}

		l.Debug("starting test execution", "test_options", to)
		if err := runTests(ctx, l, to); err != nil {
			l.Error("test execution failed", "error", err)
			fatal(l, err)
		}
		l.Debug("test execution completed successfully")
	}()

	l.Debug("waiting for completion or interruption")
	<-ctx.Done()
	l.Debug("application shutting down")
}

func fatal(l *slog.Logger, err error) {
	l.Error(err.Error())
	os.Exit(1)
}
