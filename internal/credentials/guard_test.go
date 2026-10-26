package credentials

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testCreds = Credentials{Type: "sql", Username: "u", Password: "pw"}

func acquire(t *testing.T, g *Guard, c Credentials, parallel int, retry time.Duration) (*Ticket, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	return g.Acquire(ctx, "p", c, parallel, retry)
}

func TestGuardBlocksRejectedCredentials(t *testing.T) {
	g := NewGuard()
	var events []bool
	g.OnChange = func(_ string, blocked bool) { events = append(events, blocked) }

	tk, err := acquire(t, g, testCreds, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if tk.Done(Accepted) {
		t.Fatal("accepted must not block")
	}
	tk, _ = acquire(t, g, testCreds, 2, 0)
	if !tk.Done(Rejected) {
		t.Fatal("rejection should block")
	}
	if _, err := acquire(t, g, testCreds, 2, 0); !errors.Is(err, ErrCredentialsBlocked) {
		t.Fatalf("got %v", err)
	}
	if got := g.Blocked(); len(got) != 1 || got[0] != "p" {
		t.Fatalf("Blocked() = %v", got)
	}
	// Other profiles are independent.
	if _, err := g.Acquire(context.Background(), "q", testCreds, 2, 0); err != nil {
		t.Fatal(err)
	}

	// A changed password unblocks.
	tk, err = acquire(t, g, Credentials{Type: "sql", Username: "u", Password: "new"}, 2, 0)
	if err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	tk.Done(Accepted)
	if len(events) != 2 || !events[0] || events[1] {
		t.Fatalf("events = %v", events)
	}
}

func TestGuardInconclusiveAndReset(t *testing.T) {
	g := NewGuard()
	tk, _ := acquire(t, g, testCreds, 2, 0)
	tk.Done(Inconclusive) // e.g. backend unreachable
	tk, err := acquire(t, g, testCreds, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Still unverified: one login at a time.
	if _, err := acquire(t, g, testCreds, 2, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second login while unverified: %v", err)
	}
	tk.Done(Rejected)
	if _, err := acquire(t, g, testCreds, 2, 0); err == nil {
		t.Fatal("expected block")
	}
	g.Reset()
	if _, err := acquire(t, g, testCreds, 2, 0); err != nil {
		t.Fatalf("after reset: %v", err)
	}
}

func TestGuardRetryInterval(t *testing.T) {
	g := NewGuard()
	retry := 50 * time.Millisecond
	tk, _ := acquire(t, g, testCreds, 2, retry)
	tk.Done(Rejected)
	if _, err := acquire(t, g, testCreds, 2, retry); !errors.Is(err, ErrCredentialsBlocked) {
		t.Fatal("expected block within retry interval")
	}
	time.Sleep(60 * time.Millisecond)
	tk, err := acquire(t, g, testCreds, 2, retry)
	if err != nil {
		t.Fatalf("expected one trial after the interval: %v", err)
	}
	// Only one trial: a second caller waits for its outcome.
	if _, err := acquire(t, g, testCreds, 2, retry); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second caller during trial: %v", err)
	}
	tk.Done(Rejected)
	if _, err := acquire(t, g, testCreds, 2, retry); !errors.Is(err, ErrCredentialsBlocked) {
		t.Fatalf("after failed trial: %v", err)
	}
}

// burst runs n concurrent logins with c, each rejected, and returns how many
// reached the "backend".
func burst(g *Guard, c Credentials, n, parallel int) int32 {
	var attempts atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			tk, err := g.Acquire(context.Background(), "p", c, parallel, 0)
			if err != nil {
				return
			}
			attempts.Add(1)
			time.Sleep(5 * time.Millisecond)
			tk.Done(Rejected)
		}()
	}
	close(start)
	wg.Wait()
	return attempts.Load()
}

func TestGuardUnverifiedSingleAttempt(t *testing.T) {
	if n := burst(NewGuard(), testCreds, 20, 4); n != 1 {
		t.Fatalf("%d login attempts with unverified bad credentials, want 1", n)
	}
}

func TestGuardBoundsAttemptsAfterExpiry(t *testing.T) {
	g := NewGuard()
	tk, _ := acquire(t, g, testCreds, 3, 0)
	tk.Done(Accepted)
	// The password expires server-side; at most `parallel` logins fail.
	if n := burst(g, testCreds, 20, 3); n < 1 || n > 3 {
		t.Fatalf("%d failed attempts, want 1..3", n)
	}
}

func TestGuardDoneIdempotent(t *testing.T) {
	g := NewGuard()
	tk, _ := acquire(t, g, testCreds, 1, 0)
	tk.Done(Accepted)
	tk.Done(Inconclusive) // deferred safety net
	var nilTicket *Ticket
	nilTicket.Done(Rejected)
	// One slot, and it was released exactly once.
	tk, err := acquire(t, g, testCreds, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquire(t, g, testCreds, 1, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slot released twice: %v", err)
	}
	tk.Done(Accepted)
}
