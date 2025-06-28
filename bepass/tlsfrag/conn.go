package tlsfrag

import (
	"bytes"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/markpash/heybabe/bepass/sni"
)

// Adapter represents an adapter for implementing fragmentation as net.Conn interface
type Adapter struct {
	conn         net.Conn
	readMutex    sync.Mutex
	writeMutex   sync.Mutex
	isFirstWrite bool
	logger       *slog.Logger
	// search for sni and if sni was found, initially split client hello packet to 3 packets
	// first chunk is contents of original tls hello packet before reaching sni
	// second packet is sni itself
	// and third package is contents of original tls hello packet after sni
	// we fragment each part separately BSL indicates each fragment's size(a range) for
	// original packet contents before reaching the sni
	// SL indicates each fragment's size(a range) for the sni itself
	// ASL indicates each fragment's size(a range) for remaining contents of original packet that comes after sni
	// and delay indicates how much delay system should take before sending next fragment as a separate packet
	BSL   [2]int
	SL    [2]int
	ASL   [2]int
	Delay [2]int
}

// New creates a new Adapter from a net.Conn connection.
func New(conn net.Conn, bsl, sl, asl, delay [2]int, logger *slog.Logger) *Adapter {
	logger.Debug("creating new TLS fragmentation adapter", 
		"local_addr", conn.LocalAddr(),
		"remote_addr", conn.RemoteAddr(),
		"bsl", bsl,
		"sl", sl,
		"asl", asl,
		"delay", delay)
	
	return &Adapter{
		conn:         conn,
		isFirstWrite: true,
		logger:       logger,
		BSL:          bsl,
		SL:           sl,
		ASL:          asl,
		Delay:        delay,
	}
}

// it will search for sni or host in package and if found then chunks Write writes data to the net.Conn connection.
func (a *Adapter) writeFragments(b []byte, index int) (int, error) {
	a.logger.Debug("writeFragments: starting fragmentation", 
		"data_length", len(b), 
		"fragment_index", index,
		"is_sni_fragment", index == 1)
	
	nw := 0
	position := 0
	lengthMin, lengthMax := 0, 0
	if index == 0 {
		lengthMin, lengthMax = a.BSL[0], a.BSL[1]
		a.logger.Debug("writeFragments: using BSL (before SNI) fragment sizes", "min", lengthMin, "max", lengthMax)
	} else if index == 1 { // if its sni
		lengthMin, lengthMax = a.SL[0], a.SL[1]
		a.logger.Debug("writeFragments: using SL (SNI) fragment sizes", "min", lengthMin, "max", lengthMax)
	} else { // if its after sni
		lengthMin, lengthMax = a.ASL[0], a.ASL[1]
		a.logger.Debug("writeFragments: using ASL (after SNI) fragment sizes", "min", lengthMin, "max", lengthMax)
	}
	
	fragmentCount := 0
	for position < len(b) {
		fragmentCount++
		a.logger.Debug("writeFragments: creating fragment", 
			"fragment_number", fragmentCount,
			"position", position,
			"remaining_bytes", len(b)-position)
		
		var fragmentLength int
		if lengthMax-lengthMin > 0 {
			fragmentLength = rand.Intn(lengthMax-lengthMin) + lengthMin
			a.logger.Debug("writeFragments: random fragment length", "length", fragmentLength, "range", fmt.Sprintf("%d-%d", lengthMin, lengthMax))
		} else {
			fragmentLength = lengthMin
			a.logger.Debug("writeFragments: fixed fragment length", "length", fragmentLength)
		}

		if fragmentLength > len(b)-position {
			fragmentLength = len(b) - position
			a.logger.Debug("writeFragments: adjusted fragment length to remaining data", "new_length", fragmentLength)
		}

		var delay int
		if a.Delay[1]-a.Delay[0] > 0 {
			delay = rand.Intn(a.Delay[1]-a.Delay[0]) + a.Delay[0]
			a.logger.Debug("writeFragments: random delay", "delay_ms", delay, "range", fmt.Sprintf("%d-%d", a.Delay[0], a.Delay[1]))
		} else {
			delay = a.Delay[0]
			a.logger.Debug("writeFragments: fixed delay", "delay_ms", delay)
		}

		a.logger.Debug("writeFragments: writing fragment", 
			"fragment_number", fragmentCount,
			"fragment_length", fragmentLength,
			"delay_ms", delay,
			"data_range", fmt.Sprintf("%d:%d", position, position+fragmentLength))

		tnw, ew := a.conn.Write(b[position : position+fragmentLength])
		if ew != nil {
			a.logger.Error("writeFragments: failed to write fragment", 
				"fragment_number", fragmentCount,
				"error", ew)
			return 0, ew
		}

		a.logger.Debug("writeFragments: fragment written successfully", 
			"fragment_number", fragmentCount,
			"bytes_written", tnw)

		nw += tnw
		position += fragmentLength
		
		if delay > 0 {
			a.logger.Debug("writeFragments: sleeping before next fragment", "delay_ms", delay)
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}

	a.logger.Debug("writeFragments: fragmentation completed", 
		"total_fragments", fragmentCount,
		"total_bytes_written", nw,
		"original_data_length", len(b))
	return nw, nil
}

// it will search for sni or host in package and if found then chunks Write writes data to the net.Conn connection.
func (a *Adapter) fragmentAndWriteFirstPacket(b []byte) (int, error) {
	a.logger.Debug("fragmentAndWriteFirstPacket: starting to process first packet", "packet_length", len(b))
	
	hello, err := sni.ReadClientHello(bytes.NewReader(b), a.logger)
	if err != nil {
		a.logger.Warn("fragmentAndWriteFirstPacket: failed to parse ClientHello, writing packet as-is", "error", err)
		return a.conn.Write(b)
	}
	
	a.logger.Debug("fragmentAndWriteFirstPacket: successfully parsed ClientHello", 
		"server_name", hello.ServerName,
		"tls_version", hello.Versions)
	
	helloPacketSni := []byte(hello.ServerName)
	chunks := make(map[int][]byte)

	/*
		splitting original hello packet to BeforeSNI, SNI, AfterSNI chunks
	*/
	// search for sni through original tls client hello
	a.logger.Debug("fragmentAndWriteFirstPacket: searching for SNI in packet", "sni", hello.ServerName)
	index := bytes.Index(b, helloPacketSni)
	if index == -1 {
		a.logger.Warn("fragmentAndWriteFirstPacket: SNI not found in packet, writing packet as-is")
		return a.conn.Write(b)
	}
	
	a.logger.Debug("fragmentAndWriteFirstPacket: found SNI at position", "sni_position", index, "sni_length", len(helloPacketSni))
	
	// before helloPacketSni
	chunks[0] = make([]byte, index)
	copy(chunks[0], b[:index])
	a.logger.Debug("fragmentAndWriteFirstPacket: created before-SNI chunk", "chunk_length", len(chunks[0]))
	
	// helloPacketSni
	chunks[1] = make([]byte, len(helloPacketSni))
	copy(chunks[1], b[index:index+len(helloPacketSni)])
	a.logger.Debug("fragmentAndWriteFirstPacket: created SNI chunk", "chunk_length", len(chunks[1]), "sni_content", string(chunks[1]))
	
	// after helloPacketSni
	chunks[2] = make([]byte, len(b)-index-len(helloPacketSni))
	copy(chunks[2], b[index+len(helloPacketSni):])
	a.logger.Debug("fragmentAndWriteFirstPacket: created after-SNI chunk", "chunk_length", len(chunks[2]))

	/*
		sending fragments
	*/
	// number of written packets
	nw := 0
	var ew error = nil

	a.logger.Debug("fragmentAndWriteFirstPacket: starting to send fragmented chunks")
	for i := 0; i < 3; i++ {
		chunkName := "before-SNI"
		if i == 1 {
			chunkName = "SNI"
		} else if i == 2 {
			chunkName = "after-SNI"
		}
		
		a.logger.Debug("fragmentAndWriteFirstPacket: sending chunk", 
			"chunk_index", i,
			"chunk_name", chunkName,
			"chunk_length", len(chunks[i]))
		
		tnw, ew := a.writeFragments(chunks[i], i)
		if ew != nil {
			a.logger.Error("fragmentAndWriteFirstPacket: failed to write chunk", 
				"chunk_index", i,
				"chunk_name", chunkName,
				"error", ew)
			return 0, ew
		}
		
		a.logger.Debug("fragmentAndWriteFirstPacket: chunk sent successfully", 
			"chunk_index", i,
			"chunk_name", chunkName,
			"bytes_written", tnw)
		
		nw += tnw
	}

	a.logger.Debug("fragmentAndWriteFirstPacket: all chunks sent successfully", 
		"total_bytes_written", nw,
		"original_packet_length", len(b))
	return nw, ew
}

// Write writes data to the net.Conn connection.
func (a *Adapter) Write(b []byte) (int, error) {
	a.writeMutex.Lock()
	defer a.writeMutex.Unlock()

	a.logger.Debug("Write: starting write operation", 
		"data_length", len(b),
		"is_first_write", a.isFirstWrite)

	var (
		bytesWritten int
		err          error
	)

	if a.isFirstWrite {
		a.logger.Debug("Write: processing first write with fragmentation")
		a.isFirstWrite = false
		bytesWritten, err = a.fragmentAndWriteFirstPacket(b)
	} else {
		a.logger.Debug("Write: writing data directly (not first write)")
		bytesWritten, err = a.conn.Write(b)
	}

	if err != nil {
		a.logger.Error("Write: write operation failed", "error", err, "bytes_written", bytesWritten)
	} else {
		a.logger.Debug("Write: write operation completed successfully", "bytes_written", bytesWritten)
	}

	return bytesWritten, err
}

// Read reads data from the net.Conn connection.
func (a *Adapter) Read(b []byte) (int, error) {
	// Read() can be called concurrently, and we mutate some internal state here
	a.readMutex.Lock()
	defer a.readMutex.Unlock()

	a.logger.Debug("Read: starting read operation", "buffer_size", len(b))

	bytesRead, err := a.conn.Read(b)
	if err != nil {
		a.logger.Error("Read: read operation failed", "error", err, "bytes_read", bytesRead)
		return 0, err
	}
	
	a.logger.Debug("Read: read operation completed successfully", "bytes_read", bytesRead)
	return bytesRead, err
}

// Close closes the net.Conn connection.
func (a *Adapter) Close() error {
	return a.conn.Close()
}

// LocalAddr returns the local network address.
func (a *Adapter) LocalAddr() net.Addr {
	return a.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (a *Adapter) RemoteAddr() net.Addr {
	return a.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines for the connection.
func (a *Adapter) SetDeadline(t time.Time) error {
	if err := a.SetReadDeadline(t); err != nil {
		return err
	}

	return a.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline for the connection.
func (a *Adapter) SetReadDeadline(t time.Time) error {
	return a.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline for the connection.
func (a *Adapter) SetWriteDeadline(t time.Time) error {
	return a.conn.SetWriteDeadline(t)
}
