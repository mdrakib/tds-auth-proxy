package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// LOGIN7 constants (MS-TDS 2.2.6.4).
const (
	login7FixedSize = 94
	// MaxLogin7Size bounds a LOGIN7 message. The protocol allows larger SSPI
	// blobs, but clients authenticating to the proxy use SQL authentication.
	MaxLogin7Size = 128 * 1024

	// OptionFlags2
	Flag2IntSecurity uint8 = 0x80
	// OptionFlags3
	Flag3ChangePassword uint8 = 0x01
	Flag3UserInstance   uint8 = 0x02
	Flag3Extension      uint8 = 0x10
)

// TDS versions as sent in LOGIN7 (little-endian on the wire).
const (
	TDSVersion71  uint32 = 0x71000001
	TDSVersion72  uint32 = 0x72090002
	TDSVersion73A uint32 = 0x730A0003
	TDSVersion73B uint32 = 0x730B0003
	TDSVersion74  uint32 = 0x74000004
)

// Feature extension identifiers (MS-TDS 2.2.6.4, FeatureExt).
const (
	FeatureSessionRecovery    uint8 = 0x01
	FeatureFedAuth            uint8 = 0x02
	FeatureColumnEncryption   uint8 = 0x04
	FeatureGlobalTransactions uint8 = 0x05
	FeatureAzureSQLSupport    uint8 = 0x08
	FeatureDataClassification uint8 = 0x09
	FeatureUTF8Support        uint8 = 0x0A
	FeatureAzureSQLDNSCaching uint8 = 0x0B
	FeatureJSONSupport        uint8 = 0x0D
	FeatureVectorSupport      uint8 = 0x0E
	FeatureEnhancedRouting    uint8 = 0x0F
	FeatureUserAgent          uint8 = 0x10
	FeatureTerminator         uint8 = 0xFF
)

// Feature is a single LOGIN7 FeatureExt entry.
type Feature struct {
	ID   uint8
	Data []byte
}

// Login7 is a decoded LOGIN7 message. Strings are decoded from UCS-2;
// Password and ChangePassword are stored in clear text after de-obfuscation.
type Login7 struct {
	TDSVersion     uint32
	PacketSize     uint32
	ClientProgVer  uint32
	ClientPID      uint32
	ConnectionID   uint32
	OptionFlags1   uint8
	OptionFlags2   uint8
	TypeFlags      uint8
	OptionFlags3   uint8
	ClientTimeZone int32
	ClientLCID     uint32
	ClientID       [6]byte

	HostName       string
	UserName       string
	Password       string
	AppName        string
	ServerName     string
	CltIntName     string
	Language       string
	Database       string
	AtchDBFile     string
	ChangePassword string
	SSPI           []byte
	// Features is nil when the fExtension flag is clear.
	Features []Feature
}

// offsets into the fixed part of LOGIN7 for each (ib, cch) pair.
const (
	offHostName   = 36
	offUserName   = 40
	offPassword   = 44
	offAppName    = 48
	offServerName = 52
	offExtension  = 56
	offCltIntName = 60
	offLanguage   = 64
	offDatabase   = 68
	offClientID   = 72
	offSSPI       = 78
	offAtchDBFile = 82
	offChangePwd  = 86
	offSSPILong   = 90
)

var errLogin7Bounds = errors.New("login7: field out of bounds")

// ParseLogin7 decodes and validates a LOGIN7 payload.
func ParseLogin7(b []byte) (*Login7, error) {
	if len(b) < login7FixedSize {
		return nil, errors.New("login7: message too short")
	}
	if len(b) > MaxLogin7Size {
		return nil, errors.New("login7: message too large")
	}
	le := binary.LittleEndian
	if total := le.Uint32(b[0:]); int64(total) != int64(len(b)) {
		return nil, fmt.Errorf("login7: length field %d does not match message size %d", total, len(b))
	}
	l := &Login7{
		TDSVersion:     le.Uint32(b[4:]),
		PacketSize:     le.Uint32(b[8:]),
		ClientProgVer:  le.Uint32(b[12:]),
		ClientPID:      le.Uint32(b[16:]),
		ConnectionID:   le.Uint32(b[20:]),
		OptionFlags1:   b[24],
		OptionFlags2:   b[25],
		TypeFlags:      b[26],
		OptionFlags3:   b[27],
		ClientTimeZone: int32(le.Uint32(b[28:])),
		ClientLCID:     le.Uint32(b[32:]),
	}
	copy(l.ClientID[:], b[offClientID:offClientID+6])

	str := func(off int) (string, error) {
		ib, cch := int(le.Uint16(b[off:])), int(le.Uint16(b[off+2:]))
		if cch == 0 {
			return "", nil
		}
		if ib < login7FixedSize || ib+2*cch > len(b) {
			return "", errLogin7Bounds
		}
		return decodeUCS2(b[ib : ib+2*cch]), nil
	}
	var err error
	fields := []struct {
		off int
		dst *string
	}{
		{offHostName, &l.HostName}, {offUserName, &l.UserName}, {offAppName, &l.AppName},
		{offServerName, &l.ServerName}, {offCltIntName, &l.CltIntName}, {offLanguage, &l.Language},
		{offDatabase, &l.Database}, {offAtchDBFile, &l.AtchDBFile},
	}
	for _, f := range fields {
		if *f.dst, err = str(f.off); err != nil {
			return nil, err
		}
	}
	for _, f := range []struct {
		off int
		dst *string
	}{{offPassword, &l.Password}, {offChangePwd, &l.ChangePassword}} {
		ib, cch := int(le.Uint16(b[f.off:])), int(le.Uint16(b[f.off+2:]))
		if cch == 0 {
			continue
		}
		if ib < login7FixedSize || ib+2*cch > len(b) {
			return nil, errLogin7Bounds
		}
		*f.dst = decodeUCS2(DecodePassword(b[ib : ib+2*cch]))
	}

	ibSSPI, cbSSPI := int(le.Uint16(b[offSSPI:])), int(le.Uint16(b[offSSPI+2:]))
	if cbSSPI == 0xFFFF {
		cbSSPI = int(le.Uint32(b[offSSPILong:]))
	}
	if cbSSPI > 0 {
		if ib := ibSSPI; ib < login7FixedSize || cbSSPI > len(b) || ib+cbSSPI > len(b) {
			return nil, errLogin7Bounds
		}
		l.SSPI = append([]byte(nil), b[ibSSPI:ibSSPI+cbSSPI]...)
	}

	if l.OptionFlags3&Flag3Extension != 0 {
		ib, cb := int(le.Uint16(b[offExtension:])), int(le.Uint16(b[offExtension+2:]))
		if cb != 4 || ib < login7FixedSize || ib+4 > len(b) {
			return nil, errors.New("login7: invalid extension pointer")
		}
		featOff := int(le.Uint32(b[ib:]))
		if featOff < login7FixedSize || featOff >= len(b) {
			return nil, errors.New("login7: feature extension offset out of bounds")
		}
		if l.Features, err = parseFeatures(b[featOff:]); err != nil {
			return nil, err
		}
	}
	return l, nil
}

func parseFeatures(b []byte) ([]Feature, error) {
	feats := []Feature{}
	for i := 0; ; {
		if i >= len(b) {
			return nil, errors.New("login7: feature extension missing terminator")
		}
		id := b[i]
		if id == FeatureTerminator {
			return feats, nil
		}
		if i+5 > len(b) {
			return nil, errors.New("login7: truncated feature extension")
		}
		n := binary.LittleEndian.Uint32(b[i+1:])
		if uint64(n) > uint64(len(b)-i-5) {
			return nil, errors.New("login7: feature data out of bounds")
		}
		feats = append(feats, Feature{ID: id, Data: append([]byte(nil), b[i+5:i+5+int(n)]...)})
		i += 5 + int(n)
	}
}

// Marshal encodes the LOGIN7 message, laying out all variable-length data
// freshly and recomputing every offset and length.
func (l *Login7) Marshal() ([]byte, error) {
	b := make([]byte, login7FixedSize, 512)
	le := binary.LittleEndian
	le.PutUint32(b[4:], l.TDSVersion)
	le.PutUint32(b[8:], l.PacketSize)
	le.PutUint32(b[12:], l.ClientProgVer)
	le.PutUint32(b[16:], l.ClientPID)
	le.PutUint32(b[20:], l.ConnectionID)
	b[24] = l.OptionFlags1
	b[25] = l.OptionFlags2
	b[26] = l.TypeFlags
	b[27] = l.OptionFlags3 &^ Flag3Extension
	if l.Features != nil {
		b[27] |= Flag3Extension
	}
	le.PutUint32(b[28:], uint32(l.ClientTimeZone))
	le.PutUint32(b[32:], l.ClientLCID)
	copy(b[offClientID:], l.ClientID[:])

	var err error
	putStr := func(off int, raw []byte) {
		if err != nil {
			return
		}
		if len(raw) == 0 {
			// The offset of an empty field is not significant, but keep it
			// in range when a large SSPI blob precedes it.
			le.PutUint16(b[off:], uint16(min(len(b), 0xFFFF)))
			le.PutUint16(b[off+2:], 0)
			return
		}
		if len(raw)/2 > 0xFFFF || len(b)+len(raw) > 0xFFFF {
			err = errors.New("login7: field too long")
			return
		}
		le.PutUint16(b[off:], uint16(len(b)))
		le.PutUint16(b[off+2:], uint16(len(raw)/2))
		b = append(b, raw...)
	}
	putStr(offHostName, encodeUCS2(l.HostName))
	putStr(offUserName, encodeUCS2(l.UserName))
	putStr(offPassword, EncodePassword(encodeUCS2(l.Password)))
	putStr(offAppName, encodeUCS2(l.AppName))
	putStr(offServerName, encodeUCS2(l.ServerName))
	extPtr := -1
	if l.Features != nil {
		// ibExtension points to a DWORD holding the FeatureExt offset.
		le.PutUint16(b[offExtension:], uint16(len(b)))
		le.PutUint16(b[offExtension+2:], 4)
		extPtr = len(b)
		b = append(b, 0, 0, 0, 0)
	} else {
		le.PutUint16(b[offExtension:], uint16(len(b)))
	}
	putStr(offCltIntName, encodeUCS2(l.CltIntName))
	putStr(offLanguage, encodeUCS2(l.Language))
	putStr(offDatabase, encodeUCS2(l.Database))
	if err != nil {
		return nil, err
	}

	le.PutUint16(b[offSSPI:], uint16(len(b)))
	if len(l.SSPI) >= 0xFFFF {
		le.PutUint16(b[offSSPI+2:], 0xFFFF)
		le.PutUint32(b[offSSPILong:], uint32(len(l.SSPI)))
	} else {
		le.PutUint16(b[offSSPI+2:], uint16(len(l.SSPI)))
	}
	b = append(b, l.SSPI...)

	putStr(offAtchDBFile, encodeUCS2(l.AtchDBFile))
	putStr(offChangePwd, EncodePassword(encodeUCS2(l.ChangePassword)))
	if err != nil {
		return nil, err
	}

	if extPtr >= 0 {
		le.PutUint32(b[extPtr:], uint32(len(b)))
		for _, f := range l.Features {
			b = append(b, f.ID, 0, 0, 0, 0)
			le.PutUint32(b[len(b)-4:], uint32(len(f.Data)))
			b = append(b, f.Data...)
		}
		b = append(b, FeatureTerminator)
	}
	if len(b) > MaxLogin7Size {
		return nil, errors.New("login7: message too large")
	}
	le.PutUint32(b[0:], uint32(len(b)))
	return b, nil
}

// EncodePassword applies the LOGIN7 password obfuscation to UCS-2 bytes:
// swap the nibbles of every byte, then XOR with 0xA5.
func EncodePassword(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = (c<<4 | c>>4) ^ 0xA5
	}
	return out
}

// DecodePassword reverses EncodePassword.
func DecodePassword(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		c ^= 0xA5
		out[i] = c<<4 | c>>4
	}
	return out
}

func encodeUCS2(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func decodeUCS2(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}
