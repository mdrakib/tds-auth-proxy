// Package protocol implements the subset of MS-TDS needed by the proxy:
// packet framing, PRELOGIN, TLS-over-TDS handshake transport, LOGIN7 and the
// login-response token stream.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PacketType is the first byte of a TDS packet header (MS-TDS 2.2.3.1.1).
type PacketType uint8

const (
	PacketSQLBatch    PacketType = 0x01
	PacketRPC         PacketType = 0x03
	PacketReply       PacketType = 0x04
	PacketAttention   PacketType = 0x06
	PacketBulkLoad    PacketType = 0x07
	PacketFedAuth     PacketType = 0x08
	PacketTransaction PacketType = 0x0E
	PacketLogin7      PacketType = 0x10
	PacketSSPI        PacketType = 0x11
	PacketPrelogin    PacketType = 0x12
)

// Status bits (MS-TDS 2.2.3.1.2).
const (
	StatusEOM             uint8 = 0x01
	StatusIgnore          uint8 = 0x02
	StatusResetConnection uint8 = 0x08
)

const (
	HeaderSize = 8
	// MinPacketSize and MaxPacketSize bound the negotiated packet size (MS-TDS 2.2.6.4).
	MinPacketSize = 512
	MaxPacketSize = 32767
	// DefaultPacketSize is used before LOGIN7 negotiates a different size.
	DefaultPacketSize = 4096
)

var (
	ErrPacketTooShort  = errors.New("tds: packet length shorter than header")
	ErrPacketTooLarge  = errors.New("tds: packet length exceeds limit")
	ErrMessageTooLarge = errors.New("tds: message exceeds limit")
)

// Header is a TDS packet header.
type Header struct {
	Type     PacketType
	Status   uint8
	Length   uint16 // including the header
	SPID     uint16
	PacketID uint8
	Window   uint8
}

func (h Header) EOM() bool { return h.Status&StatusEOM != 0 }

func (h Header) Marshal(b []byte) {
	b[0] = byte(h.Type)
	b[1] = h.Status
	binary.BigEndian.PutUint16(b[2:], h.Length)
	binary.BigEndian.PutUint16(b[4:], h.SPID)
	b[6] = h.PacketID
	b[7] = h.Window
}

func ParseHeader(b []byte) Header {
	return Header{
		Type:     PacketType(b[0]),
		Status:   b[1],
		Length:   binary.BigEndian.Uint16(b[2:]),
		SPID:     binary.BigEndian.Uint16(b[4:]),
		PacketID: b[6],
		Window:   b[7],
	}
}

// ReadHeader reads and validates a packet header. maxPacket bounds the
// total packet length (header included).
func ReadHeader(r io.Reader, maxPacket int) (Header, error) {
	var b [HeaderSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Header{}, err
	}
	h := ParseHeader(b[:])
	if int(h.Length) < HeaderSize {
		return h, ErrPacketTooShort
	}
	if int(h.Length) > maxPacket {
		return h, fmt.Errorf("%w: %d > %d", ErrPacketTooLarge, h.Length, maxPacket)
	}
	return h, nil
}

// Message is a complete TDS message: the payloads of all packets up to and
// including the one carrying EOM.
type Message struct {
	Type    PacketType
	SPID    uint16 // SPID from the first packet; meaningful for server replies
	Status  uint8  // status of the first packet, EOM bit excluded
	Payload []byte
}

// ReadMessage reads packets until EOM. Every packet must have the same type.
// maxPacket bounds each packet and maxMessage bounds the reassembled payload,
// so a hostile peer cannot cause unbounded allocation.
func ReadMessage(r io.Reader, maxPacket, maxMessage int) (*Message, error) {
	var m *Message
	for {
		h, err := ReadHeader(r, maxPacket)
		if err != nil {
			return nil, err
		}
		if m == nil {
			m = &Message{Type: h.Type, SPID: h.SPID, Status: h.Status &^ StatusEOM}
		} else if h.Type != m.Type {
			return nil, fmt.Errorf("tds: packet type changed mid-message (0x%02x -> 0x%02x)", m.Type, h.Type)
		}
		n := int(h.Length) - HeaderSize
		if len(m.Payload)+n > maxMessage {
			return nil, fmt.Errorf("%w: > %d bytes", ErrMessageTooLarge, maxMessage)
		}
		start := len(m.Payload)
		m.Payload = append(m.Payload, make([]byte, n)...)
		if _, err := io.ReadFull(r, m.Payload[start:]); err != nil {
			return nil, err
		}
		if h.EOM() {
			return m, nil
		}
	}
}

// WriteMessage splits payload into packets of at most packetSize bytes
// (header included) and writes them. Each packet is written with a single
// Write call so that TLS record boundaries line up with packet boundaries.
func WriteMessage(w io.Writer, typ PacketType, spid uint16, payload []byte, packetSize int) error {
	if packetSize < MinPacketSize || packetSize > MaxPacketSize {
		packetSize = DefaultPacketSize
	}
	chunk := packetSize - HeaderSize
	buf := make([]byte, 0, min(packetSize, HeaderSize+len(payload)))
	var id uint8 = 1
	for first := true; first || len(payload) > 0; first = false {
		n := min(chunk, len(payload))
		h := Header{Type: typ, Length: uint16(HeaderSize + n), SPID: spid, PacketID: id}
		if n == len(payload) {
			h.Status = StatusEOM
		}
		buf = buf[:HeaderSize]
		h.Marshal(buf)
		buf = append(buf, payload[:n]...)
		if _, err := w.Write(buf); err != nil {
			return err
		}
		payload = payload[n:]
		id++
	}
	return nil
}
