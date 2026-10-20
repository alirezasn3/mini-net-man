package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/alirezasn3/mini-net-man/internal/kernel"
	"github.com/alirezasn3/mini-net-man/internal/model"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// LoadConfig reads the YAML config. ok is false when the file doesn't exist.
func LoadConfig(path string) (cfg model.Config, ok bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, false, nil
	}
	if err != nil {
		return cfg, false, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, false, err
	}
	return cfg, true, nil
}

// SaveConfig writes the config atomically with 0600 permissions.
func SaveConfig(path string, cfg model.Config) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// DefaultConfig is what a first run starts with. Nothing is reachable except
// from localhost until the operator widens allowed_ips.
func DefaultConfig(adminPassword string) (model.Config, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return model.Config{}, err
	}
	return model.Config{
		Web: model.Web{
			Listen:     "0.0.0.0",
			Port:       8080,
			AllowedIPs: []string{"127.0.0.1", "::1"},
			Users:      []model.User{{Name: "admin", PasswordHash: string(h)}},
		},
		Firewall: model.Firewall{Policy: model.FirewallPolicy{Input: "accept", Forward: "accept", Output: "accept"}},
	}, nil
}

// state remembers what we applied last, for things the kernel can't tell us
// we own (addresses carry no owner tag).
type state struct {
	Addresses []kernel.Addr `json:"addresses"`
}

func loadState(path string) state {
	var s state
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func saveState(path string, s state) error {
	b, _ := json.Marshal(s)
	return writeAtomic(path, b)
}
