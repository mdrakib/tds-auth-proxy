// Command bench compares a direct SQL Server connection with one through the
// proxy. It needs two DSNs (go-mssqldb URL format):
//
//	go run ./tests/bench -direct 'sqlserver://...' -proxy 'sqlserver://...' [-proxy-pid N]
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func pct(d []time.Duration, p float64) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(float64(len(d)-1)*p)]
}

func connectLatency(dsn string, n int) []time.Duration {
	var out []time.Duration
	for i := 0; i < n; i++ {
		db, err := sql.Open("sqlserver", dsn)
		must(err)
		t := time.Now()
		var v int
		must(db.QueryRow("SELECT 1").Scan(&v))
		out = append(out, time.Since(t))
		db.Close()
	}
	return out
}

func queryLatency(dsn string, n int) []time.Duration {
	db, err := sql.Open("sqlserver", dsn)
	must(err)
	defer db.Close()
	db.SetMaxOpenConns(1)
	var v int
	must(db.QueryRow("SELECT 1").Scan(&v))
	out := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t := time.Now()
		must(db.QueryRow("SELECT 1").Scan(&v))
		out = append(out, time.Since(t))
	}
	return out
}

func throughput(dsn string, rows int) (float64, time.Duration) {
	db, err := sql.Open("sqlserver", dsn)
	must(err)
	defer db.Close()
	q := fmt.Sprintf(`SELECT TOP (%d) CAST(ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS BIGINT), REPLICATE('x', 200)
		FROM sys.all_objects a CROSS JOIN sys.all_objects b`, rows)
	best := time.Duration(1 << 62)
	for run := 0; run < 3; run++ {
		t := time.Now()
		r, err := db.Query(q)
		must(err)
		var n int64
		var pad string
		for r.Next() {
			must(r.Scan(&n, &pad))
		}
		r.Close()
		best = min(best, time.Since(t))
	}
	mb := float64(rows) * (8 + 200) / 1e6 // payload bytes, excluding TDS overhead
	return mb / best.Seconds(), best
}

// concurrent opens conns sessions at once (timing the login burst), then
// runs queries on all of them in parallel (timing query throughput).
func concurrent(dsn string, conns, queries int) (login time.Duration, qps float64) {
	dbs := make([]*sql.DB, conns)
	var wg sync.WaitGroup
	start := time.Now()
	for c := range dbs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := sql.Open("sqlserver", dsn)
			must(err)
			db.SetMaxOpenConns(1)
			must(db.Ping())
			dbs[c] = db
		}()
	}
	wg.Wait()
	login = time.Since(start)
	start = time.Now()
	for _, db := range dbs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var v int
			for i := 0; i < queries; i++ {
				must(db.QueryRow("SELECT 1").Scan(&v))
			}
		}()
	}
	wg.Wait()
	qps = float64(conns*queries) / time.Since(start).Seconds()
	for _, db := range dbs {
		db.Close()
	}
	return login, qps
}

func rss(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "n/a"
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "VmRSS:"))
		}
	}
	return "n/a"
}

func idleSessions(dsn string, n int) func() {
	var conns []*sql.Conn
	var dbs []*sql.DB
	for i := 0; i < n; i++ {
		db, err := sql.Open("sqlserver", dsn)
		must(err)
		c, err := db.Conn(context.Background())
		must(err)
		must(c.PingContext(context.Background()))
		conns, dbs = append(conns, c), append(dbs, db)
	}
	return func() {
		for i := range conns {
			conns[i].Close()
			dbs[i].Close()
		}
	}
}

func main() {
	direct := flag.String("direct", "", "direct DSN")
	proxy := flag.String("proxy", "", "proxy DSN")
	pid := flag.Int("proxy-pid", 0, "proxy PID for RSS measurement")
	flag.Parse()
	targets := []struct{ name, dsn string }{{"direct", *direct}, {"proxy", *proxy}}

	fmt.Println("| metric | direct | via proxy |")
	fmt.Println("|---|---|---|")
	row := func(name string, f func(dsn string) string) {
		fmt.Printf("| %s | %s | %s |\n", name, f(targets[0].dsn), f(targets[1].dsn))
	}
	row("connect + first query, p50 / p95 (50 sequential)", func(d string) string {
		l := connectLatency(d, 50)
		return fmt.Sprintf("%.1f ms / %.1f ms", ms(pct(l, .5)), ms(pct(l, .95)))
	})
	row("`SELECT 1` round trip, p50 / p99 (5000 on one conn)", func(d string) string {
		l := queryLatency(d, 5000)
		return fmt.Sprintf("%.0f µs / %.0f µs", us(pct(l, .5)), us(pct(l, .99)))
	})
	row("large result, 400k rows × 208 B (best of 3)", func(d string) string {
		mbs, t := throughput(d, 400000)
		return fmt.Sprintf("%.0f MB/s (%.2f s)", mbs, t.Seconds())
	})
	var baseline string
	if *pid != 0 {
		baseline = rss(*pid)
	}
	row("100 simultaneous logins (wall time)", func(d string) string {
		l, _ := concurrent(d, 100, 0)
		return fmt.Sprintf("%.2f s", l.Seconds())
	})
	row("`SELECT 1` throughput, 100 open conns × 200 queries", func(d string) string {
		_, qps := concurrent(d, 100, 200)
		return fmt.Sprintf("%.0f q/s", qps)
	})
	if *pid != 0 {
		fmt.Printf("\nproxy RSS: before concurrency tests %s; after login bursts %s", baseline, rss(*pid))
		done := idleSessions(*proxy, 100)
		fmt.Printf("; holding 100 open sessions %s\n", rss(*pid))
		done()
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
func us(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1000 }
