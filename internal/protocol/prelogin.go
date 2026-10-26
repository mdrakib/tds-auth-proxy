package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// PRELOGIN option tokens (MS-TDS 2.2.6.5).
const (
	PreloginVersion         uint8 = 0x00
	PreloginEncryption      uint8 = 0x01
	PreloginInstOpt         uint8 = 0x02
	PreloginThreadID        uint8 = 0x03
	PreloginMARS            uint8 = 0x04
	PreloginTraceID         uint8 = 0x05
	PreloginFedAuthRequired uint8 = 0x06
	PreloginNonceOpt        uint8 = 0x07
	PreloginTerminator      uint8 = 0xFF
)

// Encryption option values.
const (
	EncryptOff    uint8 = 0x00
	EncryptOn     uint8 = 0x01
	EncryptNotSup uint8 = 0x02
	EncryptReq    uint8 = 0x03
	// EncryptClientCert is a flag bit that may be OR-ed into the value.
	EncryptClientCert uint8 = 0x80
)

// MaxPreloginSize bounds PRELOGIN messages. Real ones are well under 100 bytes.
const MaxPreloginSize = 4096

// PreloginOption is a single PRELOGIN option.
type PreloginOption struct {
	Token uint8
	Data  []byte
}

// Prelogin is an ordered list of PRELOGIN options.
type Prelogin struct {
	Options []PreloginOption
}

// Get returns the data for token and whether it was present.
func (p *Prelogin) Get(token uint8) ([]byte, bool) {
	for _, o := range p.Options {
		if o.Token == token {
			return o.Data, true
		}
	}
	return nil, false
}

// Encryption returns the encryption option value, without the client-cert bit.
func (p *Prelogin) Encryption() (uint8, bool) {
	d, ok := p.Get(PreloginEncryption)
	if !ok || len(d) < 1 {
		return 0, false
	}
	return d[0] &^ EncryptClientCert, true
}

// MARS reports whether the MARS option is present and set.
func (p *Prelogin) MARS() bool {
	d, ok := p.Get(PreloginMARS)
	return ok && len(d) >= 1 && d[0] == 1
}

// ParsePrelogin decodes a PRELOGIN payload, validating every offset/length.
func ParsePrelogin(b []byte) (*Prelogin, error) {
	if len(b) > MaxPreloginSize {
		return nil, errors.New("prelogin: payload too large")
	}
	p := &Prelogin{}
	seen := map[uint8]bool{}
	for i := 0; ; i += 5 {
		if i >= len(b) {
			return nil, errors.New("prelogin: missing terminator")
		}
		tok := b[i]
		if tok == PreloginTerminator {
			break
		}
		if i+5 > len(b) {
			return nil, errors.New("prelogin: truncated option header")
		}
		off := int(binary.BigEndian.Uint16(b[i+1:]))
		n := int(binary.BigEndian.Uint16(b[i+3:]))
		if off+n > len(b) {
			return nil, fmt.Errorf("prelogin: option 0x%02x out of bounds", tok)
		}
		if seen[tok] {
			return nil, fmt.Errorf("prelogin: duplicate option 0x%02x", tok)
		}
		seen[tok] = true
		p.Options = append(p.Options, PreloginOption{Token: tok, Data: b[off : off+n]})
	}
	return p, nil
}

// Marshal encodes the options in order.
func (p *Prelogin) Marshal() []byte {
	hdr := 5*len(p.Options) + 1
	size := hdr
	for _, o := range p.Options {
		size += len(o.Data)
	}
	b := make([]byte, hdr, size)
	off := hdr
	for i, o := range p.Options {
		b[i*5] = o.Token
		binary.BigEndian.PutUint16(b[i*5+1:], uint16(off))
		binary.BigEndian.PutUint16(b[i*5+3:], uint16(len(o.Data)))
		off += len(o.Data)
	}
	b[hdr-1] = PreloginTerminator
	for _, o := range p.Options {
		b = append(b, o.Data...)
	}
	return b
}

// VersionOption encodes a VERSION option: 4-byte big-endian version and a
// little-endian 2-byte sub-build.
func VersionOption(major, minor uint8, build uint16) []byte {
	return []byte{major, minor, byte(build >> 8), byte(build), 0, 0}
}
