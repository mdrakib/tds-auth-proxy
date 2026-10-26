// Command tds-proxy is an authenticating TDS proxy for Microsoft SQL Server.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mdrakib/tds-auth-proxy/internal/app"
	"github.com/mdrakib/tds-auth-proxy/internal/auth"
	"github.com/mdrakib/tds-auth-proxy/internal/certgen"
	"github.com/mdrakib/tds-auth-proxy/internal/config"
	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
	"github.com/mdrakib/tds-auth-proxy/internal/session"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `usage:
  tds-proxy [run] [-config path]      run the proxy (default config: /etc/tds-proxy/config.yaml)
  tds-proxy check-config [-config path]
  tds-proxy hash-password             read a password from stdin, print an Argon2id hash
  tds-proxy healthcheck [-url url]    exit 0 if the admin /healthz endpoint answers 200
  tds-proxy gen-cert [-out dir] [-host names] [-days n] [-force]
                                      create a self-signed proxy.crt/proxy.key
  tds-proxy version
`

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = run(args)
	case "check-config":
		err = checkConfig(args)
	case "hash-password":
		err = hashPassword()
	case "gen-cert":
		err = genCert(args)
	case "version", "-version", "--version":
		fmt.Println("tds-proxy", version)
	case "healthcheck":
		err = healthcheck(args)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func configFlag(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("config", "/etc/tds-proxy/config.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *path, nil
}

func checkConfig(args []string) error {
	path, err := configFlag("check-config", args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	store := credentials.NewStore(cfg.CredentialProfiles)
	if _, err := session.BuildState(cfg, store); err != nil {
		return err
	}
	for name := range cfg.CredentialProfiles {
		if _, err := store.GetCredentials(context.Background(), name); err != nil {
			return err
		}
	}
	fmt.Println("configuration OK")
	return nil
}

func hashPassword() error {
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return err
		}
		return errors.New("no password on stdin")
	}
	pw := strings.TrimRight(sc.Text(), "\r")
	if len(pw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	h, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}

func genCert(args []string) error {
	fs := flag.NewFlagSet("gen-cert", flag.ContinueOnError)
	out := fs.String("out", ".", "directory for proxy.crt and proxy.key")
	hosts := fs.String("host", "", "comma-separated DNS names / IPs clients will connect to (default: localhost, 127.0.0.1 and this computer's name)")
	days := fs.Int("days", 825, "validity in days")
	force := fs.Bool("force", false, "replace existing files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var names []string
	for _, h := range strings.Split(*hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			names = append(names, h)
		}
	}
	if len(names) == 0 {
		names = []string{"localhost", "127.0.0.1"}
		if hn, err := os.Hostname(); err == nil && hn != "" && hn != "localhost" {
			names = append(names, hn)
		}
	}
	r, err := certgen.Generate(*out, names, time.Duration(*days)*24*time.Hour, *force)
	if err != nil {
		return err
	}
	fmt.Printf(`wrote %s and %s
  names:   %s
  expires: %s
  SHA-256: %s

Point tls.client_certificate / tls.client_private_key at these files.
Clients must trust proxy.crt (import it as a trusted root on their machine,
or into the JDBC trust store), or - for local testing only - set
TrustServerCertificate=True. Connect using one of the names above.
`, r.CertFile, r.KeyFile, strings.Join(r.Names, ", "), r.NotAfter.Format("2006-01-02"), r.SHA256)
	return nil
}

func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:8080/healthz", "health endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cl := http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get(*url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	return nil
}

func run(args []string) error {
	path, err := configFlag("run", args)
	if err != nil {
		return err
	}
	level := new(slog.LevelVar)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	a, err := app.New(path, logger, level)
	if err != nil {
		return err
	}
	if err := a.Start(); err != nil {
		return err
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigs {
		if sig != syscall.SIGHUP {
			break
		}
		logger.Info("SIGHUP received; reloading configuration")
		a.Reload()
	}
	a.Shutdown(context.Background())
	return nil
}
