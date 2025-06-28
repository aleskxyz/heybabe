package sni

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

const (
	recordHeaderLen = 5 // record header length
)

// TLS record types.
type recordType uint8

const (
	recordTypeHandshake recordType = 22
)

// TLS handshake message types.
const (
	typeClientHello uint8 = 1
)

// TLS extension numbers
var (
	extensionServerName      uint16
	extensionStatusRequest   uint16 = 5
	extensionSupportedCurves uint16 = 10
	extensionSupportedPoints uint16 = 11
	extensionSessionTicket   uint16 = 35
	extensionNextProtoNeg    uint16 = 13172 // not IANA assigned
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// A block is a simple data buffer.
type block struct {
	data []byte
	off  int // index for Read
}

// resize resizes block to be n bytes, growing if necessary.
func (b *block) resize(n int) {
	if n > cap(b.data) {
		b.reserve(n)
	}
	b.data = b.data[0:n]
}

// reserve makes sure that block contains a capacity of at least n bytes.
func (b *block) reserve(n int) {
	if cap(b.data) >= n {
		return
	}
	m := cap(b.data)
	if m == 0 {
		m = 1024
	}
	for m < n {
		m *= 2
	}
	data := make([]byte, len(b.data), m)
	copy(data, b.data)
	b.data = data
}

// readFromUntil reads from r into b until b contains at least n bytes
// or else returns an error.
func (b *block) readFromUntil(r io.Reader, n int) error {
	// quick case
	if len(b.data) >= n {
		return nil
	}

	// read until have enough.
	b.reserve(n)
	for {
		m, err := r.Read(b.data[len(b.data):cap(b.data)])
		b.data = b.data[0 : len(b.data)+m]
		if len(b.data) >= n {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *block) Read(p []byte) (n int, err error) {
	n = copy(p, b.data[b.off:])
	b.off += n
	return
}

// newBlock allocates a new block
func newBlock() *block {
	return new(block)
}

// splitBlock splits a block after the first n bytes,
// returning a block with those n bytes and a
// block with the remainder.  the latter may be nil.
func splitBlock(b *block, n int) (*block, *block) {
	if len(b.data) <= n {
		return b, nil
	}
	bb := newBlock()
	bb.resize(len(b.data) - n)
	copy(bb.data, b.data[n:])
	b.data = b.data[0:n]
	return b, bb
}

// ReadClientHello readHandshake reads the next handshake message from
// the record layer.
func ReadClientHello(rd io.Reader, l *slog.Logger) (*ClientHelloMsg, error) {
	l.Debug("starting ReadClientHello", "reader_type", fmt.Sprintf("%T", rd))
	
	var nextBlock *block  // raw input, right off the wire
	var hand bytes.Buffer // handshake data waiting to be read

	// readRecord reads the next TLS record from the connection
	// and updates the record layer state.
	readRecord := func() error {
		l.Debug("readRecord: starting to read TLS record")
		
		// Caller must be in sync with connection:
		// handshake data if handshake not yet completed,
		// else application data.  (We don't support renegotiation.)
		if nextBlock == nil {
			nextBlock = newBlock()
			l.Debug("readRecord: created new block")
		}
		b := nextBlock

		// Read header, payload.
		l.Debug("readRecord: reading record header", "header_length", recordHeaderLen)
		if err := b.readFromUntil(rd, recordHeaderLen); err != nil {
			l.Error("readRecord: failed to read record header", "error", err)
			return err
		}
		typ := recordType(b.data[0])
		l.Debug("readRecord: read record type", "type", typ, "type_hex", fmt.Sprintf("0x%02x", typ))

		// No valid TLS record has a type of 0x80, however SSLv2 handshakes
		// start with uint16 length where the MSB is set and the first record
		// is always < 256 bytes long. Therefore, typ == 0x80 strongly suggests
		// an SSLv2 client.
		if typ == 0x80 {
			l.Error("readRecord: unsupported SSLv2 handshake detected")
			return errors.New("tls: unsupported SSLv2 handshake received")
		}

		versions := uint16(b.data[1])<<8 | uint16(b.data[2])
		n := int(b.data[3])<<8 | int(b.data[4])
		l.Debug("readRecord: parsed record header", "version", versions, "version_hex", fmt.Sprintf("0x%04x", versions), "payload_length", n)

		// First message, be extra suspicious:
		// this might not be a TLS client.
		// Bail out before reading a full 'body', if possible.
		// The current max version is 3.1.
		// If the version is >= 16.0, it's probably not real.
		if (typ != recordTypeHandshake) || versions >= 0x1000 {
			l.Error("readRecord: not a valid TLS packet", "type", typ, "version", versions)
			return errors.New("not a tls packet")
		}

		l.Debug("readRecord: reading full record payload", "total_length", recordHeaderLen+n)
		if err := b.readFromUntil(rd, recordHeaderLen+n); err != nil {
			l.Error("readRecord: failed to read record payload", "error", err)
			return err
		}

		// Process message.
		b, nextBlock = splitBlock(b, recordHeaderLen+n)
		b.off = recordHeaderLen
		data := b.data[b.off : recordHeaderLen+n]
		l.Debug("readRecord: extracted handshake data", "data_length", len(data))

		hand.Write(data)
		l.Debug("readRecord: wrote data to handshake buffer", "buffer_length", hand.Len())

		return nil
	}

	l.Debug("ReadClientHello: reading first record")
	if err := readRecord(); err != nil {
		l.Error("ReadClientHello: failed to read first record", "error", err)
		return nil, err
	}

	data := hand.Bytes()
	l.Debug("ReadClientHello: got initial handshake data", "data_length", len(data))
	if len(data) < 4 {
		l.Error("ReadClientHello: handshake data too short", "length", len(data))
		return nil, errors.New("not a tls packet")
	}
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	l.Debug("ReadClientHello: parsed handshake message length", "message_length", n, "current_buffer_length", hand.Len())

	for hand.Len() < 4+n {
		l.Debug("ReadClientHello: reading additional records to complete handshake", "needed", 4+n-hand.Len())
		if err := readRecord(); err != nil {
			l.Error("ReadClientHello: failed to read additional record", "error", err)
			return nil, err
		}
	}

	data = hand.Next(4 + n)
	l.Debug("ReadClientHello: extracted complete handshake message", "message_length", len(data))
	if data[0] != typeClientHello {
		l.Error("ReadClientHello: not a ClientHello message", "message_type", data[0], "expected_type", typeClientHello)
		return nil, errors.New("not a tls packet")
	}

	l.Debug("ReadClientHello: parsing ClientHello message")
	msg := new(ClientHelloMsg)
	if !msg.unmarshal(data, l) {
		l.Error("ReadClientHello: failed to unmarshal ClientHello message")
		return nil, errors.New("not a tls packet")
	}

	l.Debug("ReadClientHello: successfully parsed ClientHello", "server_name", msg.ServerName, "version", msg.Versions)
	return msg, nil
}

// ClientHelloMsg represents a TLS ClientHello message. It contains various fields
// that store information about the client's hello message during a TLS handshake.
type ClientHelloMsg struct {
	// Raw contains the raw bytes of the ClientHello message.
	Raw                []byte
	Versions           uint16
	Random             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	NextProtoNeg       bool
	ServerName         string
	OcspStapling       bool
	SupportedCurves    []uint16
	SupportedPoints    []uint8
	TicketSupported    bool
	SessionTicket      []uint8
}

func (m *ClientHelloMsg) unmarshal(data []byte, l *slog.Logger) bool {
	l.Debug("unmarshal: starting to parse ClientHello data", "data_length", len(data))
	
	if len(data) < 42 {
		l.Error("unmarshal: data too short for ClientHello", "length", len(data), "minimum_required", 42)
		return false
	}
	m.Raw = data
	m.Versions = uint16(data[4])<<8 | uint16(data[5])
	l.Debug("unmarshal: parsed TLS version", "version", m.Versions, "version_hex", fmt.Sprintf("0x%04x", m.Versions))
	
	m.Random = data[6:38]
	l.Debug("unmarshal: extracted random data", "random_length", len(m.Random))
	
	sessionIDLen := int(data[38])
	l.Debug("unmarshal: parsed session ID length", "session_id_length", sessionIDLen)
	
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		l.Error("unmarshal: invalid session ID length", "session_id_length", sessionIDLen, "data_length", len(data))
		return false
	}
	m.SessionID = data[39 : 39+sessionIDLen]
	l.Debug("unmarshal: extracted session ID", "session_id_length", len(m.SessionID))
	
	data = data[39+sessionIDLen:]
	l.Debug("unmarshal: remaining data after session ID", "remaining_length", len(data))
	
	if len(data) < 2 {
		l.Error("unmarshal: insufficient data for cipher suites", "remaining_length", len(data))
		return false
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	l.Debug("unmarshal: parsed cipher suite length", "cipher_suite_length", cipherSuiteLen)
	
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		l.Error("unmarshal: invalid cipher suite length", "cipher_suite_length", cipherSuiteLen, "remaining_length", len(data))
		return false
	}
	numCipherSuites := cipherSuiteLen / 2
	m.CipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.CipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
	}
	l.Debug("unmarshal: parsed cipher suites", "num_cipher_suites", numCipherSuites)
	
	data = data[2+cipherSuiteLen:]
	l.Debug("unmarshal: remaining data after cipher suites", "remaining_length", len(data))
	
	if len(data) < 1 {
		l.Error("unmarshal: insufficient data for compression methods", "remaining_length", len(data))
		return false
	}
	compressionMethodsLen := int(data[0])
	l.Debug("unmarshal: parsed compression methods length", "compression_methods_length", compressionMethodsLen)
	
	if len(data) < 1+compressionMethodsLen {
		l.Error("unmarshal: invalid compression methods length", "compression_methods_length", compressionMethodsLen, "remaining_length", len(data))
		return false
	}
	m.CompressionMethods = data[1 : 1+compressionMethodsLen]
	l.Debug("unmarshal: extracted compression methods", "compression_methods_length", len(m.CompressionMethods))

	data = data[1+compressionMethodsLen:]
	l.Debug("unmarshal: remaining data after compression methods", "remaining_length", len(data))

	m.NextProtoNeg = false
	m.ServerName = ""
	m.OcspStapling = false
	m.TicketSupported = false
	m.SessionTicket = nil

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		l.Debug("unmarshal: no extensions found, ClientHello parsing complete")
		return true
	}
	if len(data) < 2 {
		l.Error("unmarshal: insufficient data for extensions", "remaining_length", len(data))
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	l.Debug("unmarshal: parsed extensions length", "extensions_length", extensionsLength)
	
	data = data[2:]
	if extensionsLength != len(data) {
		l.Error("unmarshal: extensions length mismatch", "expected_length", extensionsLength, "actual_length", len(data))
		return false
	}

	l.Debug("unmarshal: starting to parse extensions", "extensions_data_length", len(data))
	for len(data) != 0 {
		if len(data) < 4 {
			l.Error("unmarshal: insufficient data for extension header", "remaining_length", len(data))
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		l.Debug("unmarshal: parsing extension", "extension_type", extension, "extension_type_hex", fmt.Sprintf("0x%04x", extension), "extension_length", length)
		
		data = data[4:]
		if len(data) < length {
			l.Error("unmarshal: extension data too short", "expected_length", length, "remaining_length", len(data))
			return false
		}

		switch extension {
		case extensionServerName:
			l.Debug("unmarshal: processing ServerName extension")
			if length < 2 {
				l.Error("unmarshal: ServerName extension too short", "length", length)
				return false
			}
			numNames := int(data[0])<<8 | int(data[1])
			l.Debug("unmarshal: ServerName extension has names", "num_names", numNames)
			
			d := data[2:]
			for i := 0; i < numNames; i++ {
				if len(d) < 3 {
					l.Error("unmarshal: insufficient data for ServerName entry", "remaining_length", len(d))
					return false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				l.Debug("unmarshal: ServerName entry", "name_type", nameType, "name_length", nameLen)
				
				d = d[3:]
				if len(d) < nameLen {
					l.Error("unmarshal: ServerName data too short", "expected_length", nameLen, "remaining_length", len(d))
					return false
				}
				if nameType == 0 {
					m.ServerName = string(d[0:nameLen])
					l.Debug("unmarshal: extracted ServerName", "server_name", m.ServerName)
					break
				}
				d = d[nameLen:]
			}
		case extensionNextProtoNeg:
			l.Debug("unmarshal: processing NextProtoNeg extension")
			if length > 0 {
				l.Error("unmarshal: NextProtoNeg extension should be empty", "length", length)
				return false
			}
			m.NextProtoNeg = true
		case extensionStatusRequest:
			l.Debug("unmarshal: processing StatusRequest extension")
			if length < 1 {
				l.Error("unmarshal: StatusRequest extension too short", "length", length)
				return false
			}
			if data[0] == statusTypeOCSP {
				m.OcspStapling = true
				l.Debug("unmarshal: OCSP stapling enabled")
			}
		case extensionSupportedCurves:
			l.Debug("unmarshal: processing SupportedCurves extension")
			if length < 2 {
				l.Error("unmarshal: SupportedCurves extension too short", "length", length)
				return false
			}
			lVal := int(data[0])<<8 | int(data[1])
			if lVal%2 != 0 || length != lVal+2 {
				l.Error("unmarshal: SupportedCurves length mismatch or odd length", "lVal", lVal, "length", length)
				return false
			}
			numCurves := lVal / 2
			m.SupportedCurves = make([]uint16, numCurves)
			d := data[2:]
			for i := 0; i < numCurves; i++ {
				m.SupportedCurves[i] = uint16(d[0])<<8 | uint16(d[1])
				d = d[2:]
			}
			l.Debug("unmarshal: parsed supported curves", "num_curves", numCurves)
		case extensionSupportedPoints:
			l.Debug("unmarshal: processing SupportedPoints extension")
			if length < 1 {
				l.Error("unmarshal: SupportedPoints extension too short", "length", length)
				return false
			}
			lVal := int(data[0])
			if length != lVal+1 {
				l.Error("unmarshal: SupportedPoints length mismatch", "expected_length", lVal+1, "actual_length", length)
				return false
			}
			m.SupportedPoints = make([]uint8, lVal)
			copy(m.SupportedPoints, data[1:])
			l.Debug("unmarshal: parsed supported points", "num_points", lVal)
		case extensionSessionTicket:
			l.Debug("unmarshal: processing SessionTicket extension")
			m.TicketSupported = true
			m.SessionTicket = data[:length]
			l.Debug("unmarshal: extracted session ticket", "ticket_length", length)
		}
		data = data[length:]
	}

	l.Debug("unmarshal: ClientHello parsing completed successfully", 
		"server_name", m.ServerName, 
		"version", m.Versions,
		"cipher_suites_count", len(m.CipherSuites),
		"has_session_ticket", m.TicketSupported)
	return true
}
