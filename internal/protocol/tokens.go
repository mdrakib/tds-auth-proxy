package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Token types that may appear in a login response (MS-TDS 2.2.7).
const (
	TokenLoginAck      uint8 = 0xAD
	TokenEnvChange     uint8 = 0xE3
	TokenInfo          uint8 = 0xAB
	TokenError         uint8 = 0xAA
	TokenDone          uint8 = 0xFD
	TokenFeatureExtAck uint8 = 0xAE
	TokenSSPI          uint8 = 0xED
	TokenFedAuthInfo   uint8 = 0xEE
)

// ENVCHANGE types relevant to session setup.
const (
	EnvDatabase   uint8 = 1
	EnvLanguage   uint8 = 2
	EnvPacketSize uint8 = 4
	EnvCollation  uint8 = 7
	EnvRouting    uint8 = 20
)

// DONE status bits.
const (
	DoneFinal uint16 = 0x0000
	DoneMore  uint16 = 0x0001
	DoneError uint16 = 0x0002
)

// Token is one token of a login response; Raw holds the complete encoded token,
// including its type byte, so it can be re-emitted unchanged.
type Token struct {
	Type uint8
	Raw  []byte
}

// Body returns the token bytes after the type byte and length prefix.
func (t Token) Body() []byte {
	switch t.Type {
	case TokenFedAuthInfo:
		return t.Raw[5:]
	case TokenDone, TokenFeatureExtAck:
		return t.Raw[1:]
	default:
		return t.Raw[3:]
	}
}

// ParseLoginTokens splits a login-response payload into tokens. It only
// understands the token types that SQL Server sends in reply to LOGIN7 or
// SSPI messages; any other token is reported as an error, so the proxy fails
// closed instead of relaying something it cannot reason about.
func ParseLoginTokens(b []byte) ([]Token, error) {
	var toks []Token
	for i := 0; i < len(b); {
		start := i
		typ := b[i]
		i++
		var n int
		switch typ {
		case TokenLoginAck, TokenEnvChange, TokenInfo, TokenError, TokenSSPI:
			if i+2 > len(b) {
				return nil, errTokenTruncated(typ)
			}
			n = int(binary.LittleEndian.Uint16(b[i:]))
			i += 2
		case TokenFedAuthInfo:
			if i+4 > len(b) {
				return nil, errTokenTruncated(typ)
			}
			n = int(binary.LittleEndian.Uint32(b[i:]))
			i += 4
		case TokenDone:
			n = 12 // TDS 7.2+: status(2) curcmd(2) rowcount(8)
		case TokenFeatureExtAck:
			// FeatureId(1) Length(4) Data, terminated by 0xFF.
			j := i
			for {
				if j >= len(b) {
					return nil, errTokenTruncated(typ)
				}
				if b[j] == FeatureTerminator {
					j++
					break
				}
				if j+5 > len(b) {
					return nil, errTokenTruncated(typ)
				}
				l := binary.LittleEndian.Uint32(b[j+1:])
				if uint64(l) > uint64(len(b)-j-5) {
					return nil, errTokenTruncated(typ)
				}
				j += 5 + int(l)
			}
			n = j - i
		default:
			return nil, fmt.Errorf("login response: unexpected token 0x%02x", typ)
		}
		if n < 0 || n > len(b)-i {
			return nil, errTokenTruncated(typ)
		}
		i += n
		toks = append(toks, Token{Type: typ, Raw: b[start:i]})
	}
	return toks, nil
}

func errTokenTruncated(t uint8) error {
	return fmt.Errorf("login response: truncated token 0x%02x", t)
}

// DoneStatus returns the status field of a DONE token.
func DoneStatus(t Token) uint16 {
	return binary.LittleEndian.Uint16(t.Body())
}

// EnvChange is a decoded ENVCHANGE token for the string-valued types.
type EnvChange struct {
	Type     uint8
	NewValue []byte // raw value bytes (B_VARCHAR payload or B_VARBYTE)
}

// ParseEnvChange returns the type and new value of an ENVCHANGE token.
// For routing (type 20) the value is the routing structure.
func ParseEnvChange(t Token) (EnvChange, error) {
	body := t.Body()
	if len(body) < 1 {
		return EnvChange{}, errors.New("envchange: empty")
	}
	ec := EnvChange{Type: body[0]}
	rest := body[1:]
	switch ec.Type {
	case EnvRouting:
		if len(rest) < 2 {
			return ec, errors.New("envchange: truncated routing")
		}
		n := int(binary.LittleEndian.Uint16(rest))
		if 2+n > len(rest) {
			return ec, errors.New("envchange: truncated routing")
		}
		ec.NewValue = rest[2 : 2+n]
	case EnvCollation:
		if len(rest) < 1 || 1+int(rest[0]) > len(rest) {
			return ec, errors.New("envchange: truncated value")
		}
		ec.NewValue = rest[1 : 1+int(rest[0])]
	default:
		// B_VARCHAR: character count, UCS-2 data.
		if len(rest) < 1 || 1+2*int(rest[0]) > len(rest) {
			return ec, errors.New("envchange: truncated value")
		}
		ec.NewValue = rest[1 : 1+2*int(rest[0])]
	}
	return ec, nil
}

// EnvString decodes a UCS-2 ENVCHANGE value.
func EnvString(v []byte) string { return decodeUCS2(v) }

// ServerMessage is a decoded ERROR or INFO token.
type ServerMessage struct {
	Number     int32
	State      uint8
	Class      uint8
	Message    string
	ServerName string
	ProcName   string
	LineNumber int32
}

// ParseServerMessage decodes an ERROR or INFO token.
func ParseServerMessage(t Token) (ServerMessage, error) {
	b := t.Body()
	var m ServerMessage
	errShort := errors.New("server message: truncated")
	if len(b) < 8 {
		return m, errShort
	}
	m.Number = int32(binary.LittleEndian.Uint32(b))
	m.State, m.Class = b[4], b[5]
	n := int(binary.LittleEndian.Uint16(b[6:]))
	b = b[8:]
	if 2*n > len(b) {
		return m, errShort
	}
	m.Message = decodeUCS2(b[:2*n])
	b = b[2*n:]
	for _, dst := range []*string{&m.ServerName, &m.ProcName} {
		if len(b) < 1 || 1+2*int(b[0]) > len(b) {
			return m, errShort
		}
		*dst = decodeUCS2(b[1 : 1+2*int(b[0])])
		b = b[1+2*int(b[0]):]
	}
	if len(b) >= 4 {
		m.LineNumber = int32(binary.LittleEndian.Uint32(b))
	}
	return m, nil
}

// LoginAck is the decoded content of a LOGINACK token.
type LoginAck struct {
	Interface  uint8
	TDSVersion uint32
	ProgName   string
	Version    [4]byte
}

func ParseLoginAck(t Token) (LoginAck, error) {
	b := t.Body()
	var a LoginAck
	if len(b) < 6 {
		return a, errors.New("loginack: truncated")
	}
	a.Interface = b[0]
	a.TDSVersion = binary.BigEndian.Uint32(b[1:])
	n := int(b[5])
	if 6+2*n+4 > len(b) {
		return a, errors.New("loginack: truncated")
	}
	a.ProgName = decodeUCS2(b[6 : 6+2*n])
	copy(a.Version[:], b[6+2*n:])
	return a, nil
}

// ErrorToken encodes an ERROR token (TDS 7.2+ layout).
func ErrorToken(number int32, state, class uint8, msg, server string) []byte {
	m := utf16.Encode([]rune(msg))
	s := utf16.Encode([]rune(truncateRunes(server, 128)))
	if len(m) > 2048 {
		m = m[:2048]
	}
	body := make([]byte, 0, 16+2*len(m)+2*len(s))
	body = binary.LittleEndian.AppendUint32(body, uint32(number))
	body = append(body, state, class)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(m)))
	body = appendUTF16(body, m)
	body = append(body, byte(len(s)))
	body = appendUTF16(body, s)
	body = append(body, 0)                           // ProcName
	body = binary.LittleEndian.AppendUint32(body, 1) // LineNumber
	out := []byte{TokenError, 0, 0}
	binary.LittleEndian.PutUint16(out[1:], uint16(len(body)))
	return append(out, body...)
}

// DoneToken encodes a DONE token (TDS 7.2+ layout).
func DoneToken(status uint16) []byte {
	b := make([]byte, 13)
	b[0] = TokenDone
	binary.LittleEndian.PutUint16(b[1:], status)
	return b
}

func appendUTF16(b []byte, u []uint16) []byte {
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}
