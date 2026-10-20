// mini-net-man is a small web-managed Linux networking tool in the style of
// MikroTik RouterOS: routes, policy rules, addresses and an nftables firewall.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	goSystemd "github.com/alirezasn3/go-systemd"
	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/alirezasn3/mini-net-man/internal/server"
	"github.com/alirezasn3/mini-net-man/web"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

var version = "dev"

const (
	serviceName   = "mini-net-man"
	defaultConfig = "/etc/mini-net-man/config.yaml"
)

const usage = `usage: mini-net-man [command] [flags]

commands:
  run         start the daemon and web panel (default)
  install     install and start the systemd service
  uninstall   stop and remove the systemd service
  passwd USER set (or create) a panel user's password
  version     print the version

flags (run, passwd):
  -config PATH   config file (default ` + defaultConfig + `)
  -mock          run against a fake in-memory kernel (any OS), for trying the UI
`

func main() {
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = run(args)
	case "install":
		err = install(args)
	case "uninstall":
		err = goSystemd.DeleteService(serviceName)
	case "passwd":
		err = passwd(args)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type flags struct {
	config string
	mock   bool
	rest   []string
}

func parse(name string, args []string) (flags, error) {
	var f flags
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&f.config, "config", "", "config file")
	fs.BoolVar(&f.mock, "mock", false, "use the fake kernel")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	f.rest = fs.Args()
	if f.config == "" {
		f.config = defaultConfig
		if f.mock {
			f.config = "mock-config.yaml"
		}
	}
	return f, nil
}

func run(args []string) error {
	f, err := parse("run", args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var k kernel.Kernel
	if f.mock {
		k = kernel.NewMock()
	} else if k, err = kernel.New(); err != nil {
		return err
	} else if os.Geteuid() != 0 {
		return errors.New("must run as root (or use -mock to try the UI)")
	}

	cfg, ok, err := engine.LoadConfig(f.config)
	if err != nil {
		return fmt.Errorf("reading %s: %w", f.config, err)
	}
	if !ok {
		pw := randomPassword()
		if cfg, err = engine.DefaultConfig(pw); err != nil {
			return err
		}
		if err := engine.SaveConfig(f.config, cfg); err != nil {
			return err
		}
		fmt.Printf("\nFirst run: wrote %s\n  panel login:  admin / %s\n  listening on: %s:%d, reachable only from %v\n  (change with `mini-net-man passwd admin`, and widen allowed_ips in the panel or config)\n\n",
			f.config, pw, cfg.Web.Listen, cfg.Web.Port, cfg.Web.AllowedIPs)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	eng := engine.New(k, cfg, f.config, log)
	eng.Start()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go eng.Run(ctx)

	return server.New(eng, web.FS(), f.config, f.mock, log).ListenAndServe(ctx)
}

func install(args []string) error {
	f, err := parse("install", args)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cfg, _ := filepath.Abs(f.config)
	return goSystemd.CreateService(&goSystemd.Service{
		Name:        serviceName,
		Description: "mini-net-man network manager",
		ExecStart:   fmt.Sprintf("%s run -config %s", exe, cfg),
		Restart:     "on-failure",
		RestartSec:  "3s",
		After:       "network-online.target",
		Wants:       "network-online.target",
	})
}

func passwd(args []string) error {
	f, err := parse("passwd", args)
	if err != nil {
		return err
	}
	if len(f.rest) != 1 {
		return errors.New("usage: mini-net-man passwd USER [-config PATH]")
	}
	user := f.rest[0]
	cfg, ok, err := engine.LoadConfig(f.config)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s does not exist yet; run the daemon once first", f.config)
	}
	fmt.Fprintf(os.Stderr, "New password for %s: ", user)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if len(pw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	h, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	found := false
	for i := range cfg.Web.Users {
		if cfg.Web.Users[i].Name == user {
			cfg.Web.Users[i].PasswordHash, found = string(h), true
		}
	}
	if !found {
		cfg.Web.Users = append(cfg.Web.Users, model.User{Name: user, PasswordHash: string(h)})
	}
	if err := engine.SaveConfig(f.config, cfg); err != nil {
		return err
	}
	fmt.Println("saved; restart the service for it to take effect: systemctl restart", serviceName)
	return nil
}

func randomPassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
