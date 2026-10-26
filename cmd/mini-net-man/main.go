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
	"runtime"
	"strings"
	"syscall"
	"time"

	goSystemd "github.com/alirezasn3/go-systemd"
	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
	"github.com/alirezasn3/mini-net-man/internal/server"
	"github.com/alirezasn3/mini-net-man/internal/update"
	"github.com/alirezasn3/mini-net-man/web"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

var version = "dev"

const serviceName = "mini-net-man"

const usage = `usage: mini-net-man [command] [flags]

commands:
  run         start the daemon and web panel (default)
  install     set everything up and start it as a systemd service
  update      install the latest release from GitHub (-check to only look)
  uninstall   stop and remove the systemd service (keeps your config)
  passwd USER set (or create) a panel user's password
  version     print the version

The config file is config.yaml next to this binary unless -config says otherwise.

install flags:
  -allow IPS     IPs or CIDRs to allow into the panel, comma separated, in
                 addition to this machine (the default is this machine only)
  -port N        panel port (default 8080)
  -config PATH   config file

update flags:
  -check         only report whether a newer release exists
  -version TAG   install that release instead of the latest (can go back)
  -rollback      go back to the version before the last update
  -force         reinstall even if already up to date
  -no-restart    don't restart the service afterwards
  -repo OWNER/NAME   GitHub repository (default: the project's own)

run and passwd flags:
  -config PATH   config file
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
	case "update":
		err = updateCmd(args)
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

// defaultConfigPath is config.yaml in the directory of the running binary
// (symlinks resolved), so the binary and its settings travel together.
func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "config.yaml"
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Join(filepath.Dir(exe), "config.yaml")
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
		f.config = defaultConfigPath()
		if f.mock {
			f.config = "mock-config.yaml"
		}
	}
	if abs, err := filepath.Abs(f.config); err == nil {
		f.config = abs
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

	cfg, pw, err := ensureConfig(f.config)
	if err != nil {
		return err
	}
	if pw != "" {
		fmt.Print(firstRunNotice(f.config, cfg, pw))
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	eng := engine.New(k, cfg, f.config, log)
	eng.Start()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go eng.Run(ctx)

	return server.New(eng, web.FS(), f.config, f.mock, version, log).ListenAndServe(ctx)
}

// ensureConfig loads the config, writing a default one (with a random admin
// password, returned once) if the file does not exist yet.
func ensureConfig(path string) (cfg model.Config, newPassword string, err error) {
	cfg, ok, err := engine.LoadConfig(path)
	if err != nil {
		return cfg, "", fmt.Errorf("reading %s: %w", path, err)
	}
	if ok {
		return cfg, "", nil
	}
	pw := randomPassword()
	if cfg, err = engine.DefaultConfig(pw); err != nil {
		return cfg, "", err
	}
	if err := engine.SaveConfig(path, cfg); err != nil {
		return cfg, "", err
	}
	return cfg, pw, nil
}

func listenText(cfg model.Config) string {
	if ip := cfg.Web.Listen; ip == "0.0.0.0" || ip == "::" || ip == "" {
		return fmt.Sprintf("port %d on all addresses", cfg.Web.Port)
	}
	return fmt.Sprintf("%s:%d", cfg.Web.Listen, cfg.Web.Port)
}

func firstRunNotice(path string, cfg model.Config, pw string) string {
	return fmt.Sprintf("\nCreated %s\n  login:    admin / %s   (change it with `mini-net-man passwd admin`)\n  panel:    %s\n  allowed:  %s\n\n",
		path, pw, listenText(cfg), strings.Join(cfg.Web.AllowedIPs, ", "))
}

// install does everything in one step: config file, systemd unit, start.
// Running it again after replacing the binary restarts the service on it.
func install(args []string) error {
	var allow string
	var port int
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	cfgFlag := fs.String("config", "", "config file")
	fs.StringVar(&allow, "allow", "", "allowed IPs or CIDRs, comma separated")
	fs.IntVar(&port, "port", 0, "panel port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("install only works on Linux (it creates a systemd service)")
	}
	if os.Geteuid() != 0 {
		return errors.New("install needs root: run `sudo ./mini-net-man install`")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	cfgPath := *cfgFlag
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if cfgPath, err = filepath.Abs(cfgPath); err != nil {
		return err
	}

	cfg, pw, err := ensureConfig(cfgPath)
	if err != nil {
		return err
	}
	changed := false
	if allow != "" {
		// Additive: localhost stays allowed, so an SSH tunnel always works.
		cfg.Web.AllowedIPs = mergeUnique(cfg.Web.AllowedIPs, splitList(allow))
		changed = true
	}
	if port != 0 {
		cfg.Web.Port = port
		changed = true
	}
	if changed {
		if err := cfg.Validate(); err != nil {
			return err
		}
		if err := engine.SaveConfig(cfgPath, cfg); err != nil {
			return err
		}
	}

	// Replace a running copy so the new binary takes over.
	if st, err := goSystemd.StatusService(serviceName); err == nil && st != nil && st.Exists {
		_ = goSystemd.StopService(serviceName)
	}
	if err := goSystemd.CreateService(&goSystemd.Service{
		Name:        serviceName,
		Description: "mini-net-man network manager",
		ExecStart:   fmt.Sprintf("%s run -config %s", exe, cfgPath),
		Restart:     "on-failure",
		RestartSec:  "3s",
		After:       "network-online.target",
		Wants:       "network-online.target",
	}); err != nil {
		return err
	}

	if pw != "" {
		fmt.Print(firstRunNotice(cfgPath, cfg, pw))
	} else {
		fmt.Printf("\nUsing existing config %s\n  panel:    %s\n  allowed:  %s\n\n", cfgPath, listenText(cfg), strings.Join(cfg.Web.AllowedIPs, ", "))
	}
	fmt.Printf("Installed and started the %s service, running %s\n", serviceName, exe)
	fmt.Println("Keep the binary where it is (the service runs it in place); if you move it, run install again.")
	fmt.Printf("Logs: journalctl -u %s -f     Remove: %s uninstall\n", serviceName, exe)
	return nil
}

func mergeUnique(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range append(append([]string{}, a...), b...) {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, p)
	}
	return out
}

// updateCmd implements `mini-net-man update`.
func updateCmd(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "only report whether a newer release exists")
	want := fs.String("version", "", "release tag to install")
	rollback := fs.Bool("rollback", false, "go back to the previous version")
	force := fs.Bool("force", false, "reinstall even if up to date")
	noRestart := fs.Bool("no-restart", false, "do not restart the service")
	repo := fs.String("repo", "", "GitHub repository, owner/name")
	api := fs.String("api", "", "GitHub API base URL (GitHub Enterprise, or tests)")
	cfgFlag := fs.String("config", "", "config file (for update.repo)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	exe, err := update.Executable()
	if err != nil {
		return err
	}

	if *rollback {
		if err := update.Rollback(exe); err != nil {
			return err
		}
		fmt.Println("Went back to the previous version.")
		return restartAfter(*noRestart)
	}

	if *repo == "" {
		cfgPath := *cfgFlag
		if cfgPath == "" {
			cfgPath = defaultConfigPath()
		}
		if cfg, ok, err := engine.LoadConfig(cfgPath); err == nil && ok {
			*repo = cfg.Update.Repo
		}
	}
	client := update.New(*repo)
	if *api != "" {
		client.APIBase = strings.TrimRight(*api, "/")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var rel *update.Release
	if *want != "" {
		rel, err = client.ByTag(ctx, *want)
	} else {
		rel, err = client.Latest(ctx)
	}
	if err != nil {
		return err
	}

	newer, cmpErr := update.Newer(version, rel.Tag)
	fmt.Printf("installed: %s\nlatest:    %s  %s\n", version, rel.Tag, rel.URL)
	switch {
	case *check:
		switch {
		case cmpErr != nil:
			fmt.Println("This build has no release version, so it can't tell. Use `update -force` to install the latest release anyway.")
		case newer:
			fmt.Printf("A newer release is available. Install it with: sudo %s update\n", exe)
		default:
			fmt.Println("Up to date.")
		}
		return nil
	case *want == "" && cmpErr == nil && !newer && !*force:
		fmt.Println("Already up to date.")
		return nil
	case cmpErr != nil && !*force && *want == "":
		return fmt.Errorf("%w; use -force to install %s anyway, or -version to pick a release", cmpErr, rel.Tag)
	}

	fmt.Printf("Downloading %s ...\n", update.AssetName())
	done, err := client.Install(ctx, rel, exe)
	if err != nil {
		return err
	}
	if done.Previous != "" {
		fmt.Printf("Updated %s -> %s (previous binary kept as %s; `update -rollback` goes back)\n", version, rel.Tag, done.Previous)
	} else {
		fmt.Printf("Reinstalled %s.\n", rel.Tag)
	}
	return restartAfter(*noRestart)
}

// restartAfter restarts the service on the new binary, if there is one.
func restartAfter(skip bool) error {
	st, err := goSystemd.StatusService(serviceName)
	if err != nil || st == nil || !st.Exists || !st.Active {
		fmt.Println("The service is not running; start it with `sudo ./mini-net-man install`, or run the new binary yourself.")
		return nil
	}
	if skip {
		fmt.Println("Restart it to use the new version: sudo systemctl restart " + serviceName)
		return nil
	}
	if err := update.RestartService(serviceName, false); err != nil {
		fmt.Println("Could not restart the service automatically:", err)
		fmt.Println("Restart it yourself: sudo systemctl restart " + serviceName)
		return nil
	}
	fmt.Println("Restarted the service.")
	return nil
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
	if err := model.ValidUsername(user); err != nil {
		return err
	}
	cfg, ok, err := engine.LoadConfig(f.config)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s does not exist yet; run `mini-net-man install` (or `run`) once first", f.config)
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
