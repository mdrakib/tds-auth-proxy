package relay

import (
	"io"
	"sync/atomic"
	"testing/iotest"
)

type atomicInt64 struct{ v atomic.Int64 }

func (a *atomicInt64) ptr() *atomic.Int64 { return &a.v }

// iotestOneByte returns a reader that yields one byte per Read, exercising
// partial reads.
func iotestOneByte(r io.Reader) io.Reader { return iotest.OneByteReader(r) }
