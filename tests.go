package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
)

type TestOptions struct {
	ResolveIPv4 bool
	ResolveIPv6 bool
	ManualIP    netip.Addr
	Port        uint16
	SNI         string
	Repeat      uint
}

type TestResult struct {
	AddrPort netip.AddrPort
	SNI      string
	Attempts []TestAttemptResult
}

type TestAttemptResult struct {
	TransportEstablishDuration time.Duration
	TLSHandshakeDuration       time.Duration
	err                        error
}

type testFunc func(context.Context, *slog.Logger, netip.AddrPort, string) TestAttemptResult

// Represents a single test function and its label.
type testCase struct {
	fn    testFunc
	label string
}

// Holds all tests in the exact order we want to execute and display.
var testSuite = []testCase{
	{fn: test_TCP_TLS12_Default, label: "Default - TCP - TLS 1.2"},
	{fn: test_TCP_TLS13_Default, label: "Default - TCP - TLS 1.3"},
	{fn: test_TCP_TLS13_UTLS_ChromeAuto_Default, label: "Default - TCP - TLS 1.3 - uTLS ChromeAuto"},
	{fn: test_QUIC_TLS13_UQUIC_Chrome_115_Default, label: "Default - QUIC - TLS 1.3 - uQUIC Chrome"},
	{fn: test_TCP_TLS13_UTLS_ChromeAuto_bepass_fragment, label: "Bepass Fragment - TCP - TLS 1.3 - uTLS ChromeAuto"},
	{fn: test_TCP_TLS_warp_plus_custom, label: "WarpPlus Custom - TCP - TLS 1.2"},
}

func runTests(ctx context.Context, l *slog.Logger, to TestOptions) error {
	l = l.With("sni", to.SNI, "port", to.Port)
	
	l.Debug("starting test suite execution", 
		"resolve_ipv4", to.ResolveIPv4,
		"resolve_ipv6", to.ResolveIPv6,
		"manual_ip", to.ManualIP,
		"repeat_count", to.Repeat)

	testAddrPorts := []netip.AddrPort{}
	if to.ManualIP == netip.IPv4Unspecified() {
		l.Debug("manual IP not specified, attempting DNS resolution")

		// Resolve DNS
		var err error
		v4, v6, err := resolve(ctx, to.SNI, to.ResolveIPv4, to.ResolveIPv6)
		if err != nil {
			l.Error("DNS resolution failed", "error", err)
			return fmt.Errorf("failed to resolve SNI: %w", err)
		}

		l.Debug("DNS resolution completed", "ipv4", v4, "ipv6", v6)

		if to.ResolveIPv4 && v4 != netip.IPv4Unspecified() {
			testAddrPorts = append(testAddrPorts, netip.AddrPortFrom(v4, to.Port))
			l.Debug("added IPv4 address to test targets", "ipv4", v4)
		}

		if to.ResolveIPv6 && v6 != netip.IPv6Unspecified() {
			testAddrPorts = append(testAddrPorts, netip.AddrPortFrom(v6, to.Port))
			l.Debug("added IPv6 address to test targets", "ipv6", v6)
		}
	} else {
		l.Debug("manual IP specified, proceeding with the provided IP", "manual_ip", to.ManualIP)
		testAddrPorts = append(testAddrPorts, netip.AddrPortFrom(to.ManualIP, to.Port))
	}

	l.Debug("test targets determined", "target_count", len(testAddrPorts), "targets", testAddrPorts)

	results := make(map[string][]TestResult)
	labelOrder := make([]string, 0, len(testSuite))

	l.Debug("starting test execution", "test_count", len(testSuite))
	for i, tc := range testSuite {
		l.Debug("executing test", "test_index", i+1, "test_name", tc.label, "test_count", len(testSuite))
		
		test := tc.fn
		resultsPerTest := make([]TestResult, len(testAddrPorts))
		for x, addrPort := range testAddrPorts {
			l.Debug("testing target", "target_index", x+1, "target", addrPort.String())
			
			tr := TestResult{AddrPort: addrPort, SNI: to.SNI, Attempts: make([]TestAttemptResult, to.Repeat)}
			for j := uint(0); j < to.Repeat; j++ {
				l.Debug("executing test attempt", "attempt", j+1, "total_attempts", to.Repeat)
				
				// Create a context with 10-second timeout for each individual test
				testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				tr.Attempts[j] = test(testCtx, l, addrPort, to.SNI)
				cancel() // Always cancel to release resources
				
				if tr.Attempts[j].err != nil {
					l.Debug("test attempt failed", "attempt", j+1, "error", tr.Attempts[j].err)
				} else {
					l.Debug("test attempt succeeded", "attempt", j+1, 
						"transport_duration", tr.Attempts[j].TransportEstablishDuration,
						"tls_duration", tr.Attempts[j].TLSHandshakeDuration)
				}
				
				if j < to.Repeat-1 {
					l.Debug("waiting between attempts", "wait_duration", "2s")
					time.Sleep(2 * time.Second)
				}
			}
			resultsPerTest[x] = tr
		}
		results[tc.label] = resultsPerTest
		labelOrder = append(labelOrder, tc.label)
		
		if i < len(testSuite)-1 {
			l.Debug("waiting between test types", "wait_duration", "2s")
			// 2-second delay between different test types
			time.Sleep(2 * time.Second)
		}
	}

	l.Debug("all tests completed, generating results table")
	printTable(results, labelOrder)
	l.Debug("test suite execution completed")

	return nil
}

func printTable(results map[string][]TestResult, order []string) {
	headerFmt := color.New(color.FgHiMagenta, color.Bold, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgHiCyan, color.Bold).SprintfFunc()

	tbl := table.New("Test Method", "SNI", "IP:Port", "Handshake Status", "Transport Time", "TLS Handshake Time")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, testName := range order {
		testResults := results[testName]
		for _, testResult := range testResults {
			var (
				successCount   int
				totalTransport time.Duration
				totalTLS       time.Duration
			)

			for _, attempt := range testResult.Attempts {
				if attempt.err == nil {
					successCount++
					totalTransport += attempt.TransportEstablishDuration
					totalTLS += attempt.TLSHandshakeDuration
				}
			}

			totalAttempts := len(testResult.Attempts)
			var status string
			switch {
			case successCount == 0:
				status = fmt.Sprintf("Failed  (%d/%d)", successCount, totalAttempts)
			case successCount == totalAttempts:
				status = fmt.Sprintf("Success (%d/%d)", successCount, totalAttempts)
			default:
				status = fmt.Sprintf("Partial (%d/%d)", successCount, totalAttempts)
			}

			var avgTransport, avgTLS time.Duration
			if successCount > 0 {
				avgTransport = totalTransport / time.Duration(successCount)
				avgTLS = totalTLS / time.Duration(successCount)
			}

			formatDur := func(d time.Duration) string {
				if d == 0 {
					return "0 ms"
				}
				return fmt.Sprintf("%.1f ms", float64(d)/float64(time.Millisecond))
			}

			tbl.AddRow(
				testName,
				testResult.SNI,
				testResult.AddrPort,
				status,
				formatDur(avgTransport),
				formatDur(avgTLS),
			)
		}
	}

	fmt.Println("")
	tbl.Print()
	fmt.Println("")
}

func resolve(ctx context.Context, hostname string, getv4, getv6 bool) (v4, v6 netip.Addr, err error) {
	v4, v6 = netip.IPv4Unspecified(), netip.IPv6Unspecified()

	addrs, err := (&net.Resolver{PreferGo: true}).LookupHost(ctx, hostname)
	if err != nil {
		return v4, v6, err
	}

	// I'm lazy, parse all addresses
	parsedAddrs := make([]netip.Addr, len(addrs))
	for i, addr := range addrs {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return v4, v6, err
		}
		parsedAddrs[i] = ip.Unmap()
	}

	// Find the first v4 address
	if getv4 {
		for _, addr := range parsedAddrs {
			if addr.Is4() {
				v4 = addr
				break
			}
		}
	}

	// Find the first v6 address
	if getv6 {
		for _, addr := range parsedAddrs {
			if addr.Is6() {
				v6 = addr
				break
			}
		}
	}

	return v4, v6, nil
}

func GetFunctionName(temp interface{}) string {
	strs := strings.Split((runtime.FuncForPC(reflect.ValueOf(temp).Pointer()).Name()), ".")
	return strs[len(strs)-1]
}
