package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func tdsPacket(n int) []byte {
	b := make([]byte, n)
	b[0], b[1] = 0x01, 0x01
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	for i := 8; i < n; i++ {
		b[i] = byte(i)
	}
	return b
}

func smpFrame(n int) []byte {
	b := make([]byte, n)
	b[0] = smpID
	binary.LittleEndian.PutUint32(b[4:], uint32(n))
	return b
}

type countingWriter struct {
	bytes.Buffer
	writes []int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, len(p))
	return w.Buffer.Write(p)
}

func TestCopyFramesPreservesBoundaries(t *testing.T) {
	var in bytes.Buffer
	frames := [][]byte{tdsPacket(8), tdsPacket(4096), smpFrame(16), smpFrame(16 + 100), tdsPacket(32767)}
	for _, f := range frames {
		in.Write(f)
	}
	var out countingWriter
	var seen = new(atomicInt64)
	n, rerr, werr := copyFrames(&out, iotestOneByte(&in), seen.ptr(), nil, true)
	if rerr != io.EOF || werr != nil {
		t.Fatal(rerr, werr)
	}
	want := []int{8, 4096, 16, 116, 32767}
	if len(out.writes) != len(want) {
		t.Fatalf("writes %v", out.writes)
	}
	for i := range want {
		if out.writes[i] != want[i] {
			t.Fatalf("writes %v want %v", out.writes, want)
		}
	}
	if n != int64(8+4096+16+116+32767) {
		t.Fatal("byte count", n)
	}
}

func TestCopyFramesRejectsInvalidLengths(t *testing.T) {
	bad := tdsPacket(8)
	binary.BigEndian.PutUint16(bad[2:], 4)
	// uint16 lengths above MaxPacketSize used to slice past the buffer and
	// panic, crashing the whole process.
	oversized := tdsPacket(8)
	binary.BigEndian.PutUint16(oversized[2:], 0xFFFF)
	badSMP := smpFrame(16)
	binary.LittleEndian.PutUint32(badSMP[4:], 1<<20)
	for _, b := range [][]byte{bad, oversized, badSMP} {
		_, rerr, _ := copyFrames(io.Discard, bytes.NewReader(b), new(atomicInt64).ptr(), nil, true)
		if rerr == nil || rerr == io.EOF {
			t.Fatalf("expected framing error, got %v", rerr)
		}
	}
}

func TestRunClosesBothSides(t *testing.T) {
	c1, c2 := net.Pipe()
	b1, b2 := net.Pipe()
	done := make(chan Result)
	go func() { done <- Run(context.Background(), c2, b1, 0, nil) }()

	go c1.Write(tdsPacket(100))
	got := make([]byte, 100)
	if _, err := io.ReadFull(b2, got); err != nil || !bytes.Equal(got, tdsPacket(100)) {
		t.Fatal("not relayed", err)
	}
	go b2.Write(tdsPacket(50))
	if _, err := io.ReadFull(c1, got[:50]); err != nil {
		t.Fatal(err)
	}
	c1.Close()
	r := <-done
	if r.Reason != ReasonClientClosed || r.ClientToBack != 100 || r.BackToClient != 50 {
		t.Fatalf("%+v", r)
	}
	if _, err := b2.Write([]byte{1}); err == nil {
		t.Fatal("backend side not closed")
	}
}

func TestRunIdleTimeoutAndCancel(t *testing.T) {
	c1, c2 := net.Pipe()
	b1, _ := net.Pipe()
	defer c1.Close()
	start := time.Now()
	r := Run(context.Background(), c2, b1, 100*time.Millisecond, nil)
	if r.Reason != ReasonIdleTimeout || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v after %v", r, time.Since(start))
	}

	c1, c2 = net.Pipe()
	b1, _ = net.Pipe()
	defer c1.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if r := Run(ctx, c2, b1, 0, nil); r.Reason != ReasonShutdown {
		t.Fatalf("%+v", r)
	}
}

func TestRunSurvivesOversizedHeader(t *testing.T) {
	c1, c2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer b2.Close()
	done := make(chan Result)
	go func() { done <- Run(context.Background(), c2, b1, 0, nil) }()
	go b2.Write([]byte{0x04, 0x01, 0xFF, 0xFF, 0, 0, 1, 0})
	r := <-done
	c1.Close()
	if r.Reason != ReasonBackendError || r.Err == nil {
		t.Fatalf("%+v", r)
	}
}
