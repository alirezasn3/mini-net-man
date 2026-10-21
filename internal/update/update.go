// Package update installs new versions of mini-net-man from GitHub Releases.
//
// A release is expected to carry one binary per platform, named
// mini-net-man-<os>-<arch>, plus a checksums.txt in `sha256sum` format. The
// binary is verified against that file, test-run (`<binary> version` must
// print the release tag), and only then swapped in with a rename. The
// previous binary is kept as <exe>.old so an update can be undone.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultRepo    = "alirezasn3/mini-net-man"
	DefaultAPIBase = "https://api.github.com"
	ChecksumsAsset = "checksums.txt"
	maxBinaryBytes = 200 << 20
)

// Client talks to the GitHub releases API.
type Client struct {
	Repo    string // owner/name
	APIBase string
	Token   string // optional, for private repositories
	HTTP    *http.Client
}

// New returns a client for repo ("" means DefaultRepo). Two environment
// variables adjust it: MINI_NET_MAN_GITHUB_TOKEN (a token, for private
// repositories) and MINI_NET_MAN_API (the API base URL, for GitHub Enterprise
// or tests).
func New(repo string) *Client {
	if repo == "" {
		repo = DefaultRepo
	}
	base := DefaultAPIBase
	if v := os.Getenv("MINI_NET_MAN_API"); v != "" {
		base = strings.TrimRight(v, "/")
	}
	return &Client{Repo: repo, APIBase: base, Token: os.Getenv("MINI_NET_MAN_GITHUB_TOKEN"),
		HTTP: &http.Client{Timeout: 2 * time.Minute}}
}

type Asset struct {
	Name   string `json:"name"`
	APIURL string `json:"url"`
	URL    string `json:"browser_download_url"`
	Size   int64  `json:"size"`
}

type Release struct {
	Tag    string  `json:"tag_name"`
	URL    string  `json:"html_url"`
	Notes  string  `json:"body"`
	Assets []Asset `json:"assets"`
}

// AssetName is the binary name for this platform.
func AssetName() string { return fmt.Sprintf("mini-net-man-%s-%s", runtime.GOOS, runtime.GOARCH) }

func (r *Release) asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

func (c *Client) get(ctx context.Context, url, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "mini-net-man-updater")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return c.HTTP.Do(req)
}

func (c *Client) release(ctx context.Context, path string) (*Release, error) {
	resp, err := c.get(ctx, c.APIBase+"/repos/"+c.Repo+"/releases/"+path, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("no such release in %s (is the repository public, and does it have a published release?)", c.Repo)
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return nil, errors.New("GitHub refused the request (rate limit?); try again later")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub answered %s", resp.Status)
	}
	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("reading release: %w", err)
	}
	if rel.Tag == "" {
		return nil, errors.New("release has no tag")
	}
	return &rel, nil
}

// Latest returns the newest published (non-prerelease) release.
func (c *Client) Latest(ctx context.Context) (*Release, error) { return c.release(ctx, "latest") }

// ByTag returns a specific release, such as "v1.2.3".
func (c *Client) ByTag(ctx context.Context, tag string) (*Release, error) {
	return c.release(ctx, "tags/"+tag)
}

// ---- versions --------------------------------------------------------------

type semver struct {
	nums [3]int
	pre  string
}

// parseVersion accepts only "v"-prefixed versions. Release tags always are,
// and the prefix keeps an all-digit commit hash from passing for a version.
func parseVersion(v string) (semver, bool) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "v") {
		return semver{}, false
	}
	v = v[1:]
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var s semver
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, s.pre = v[:i], v[i+1:]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return s, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return s, false
		}
		s.nums[i] = n
	}
	return s, true
}

// Comparable reports whether v looks like a release version (v1.2.3). Builds
// from a branch ("dev", a commit hash) are not.
func Comparable(v string) bool { _, ok := parseVersion(v); return ok }

// Newer reports whether candidate is a later release than current. A
// pre-release (v1.2.3-rc1) ranks below the final v1.2.3.
func Newer(current, candidate string) (bool, error) {
	c, ok := parseVersion(current)
	if !ok {
		return false, fmt.Errorf("current version %q is not a release version", current)
	}
	n, ok := parseVersion(candidate)
	if !ok {
		return false, fmt.Errorf("release tag %q is not a version", candidate)
	}
	for i := range c.nums {
		if n.nums[i] != c.nums[i] {
			return n.nums[i] > c.nums[i], nil
		}
	}
	switch {
	case c.pre == n.pre:
		return false, nil
	case c.pre != "" && n.pre == "":
		return true, nil
	case c.pre == "" && n.pre != "":
		return false, nil
	}
	return n.pre > c.pre, nil
}

// ---- installing ------------------------------------------------------------

// parseChecksums reads `sha256sum` output and returns the hash for name.
func parseChecksums(r io.Reader, name string) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("%s has no checksum for %s", ChecksumsAsset, name)
}

func (c *Client) download(ctx context.Context, a Asset) (*http.Response, error) {
	url, accept := a.URL, "application/octet-stream"
	if c.Token != "" && a.APIURL != "" {
		url = a.APIURL // private repositories only serve assets through the API
	}
	resp, err := c.get(ctx, url, accept)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("downloading %s: %s", a.Name, resp.Status)
	}
	return resp, nil
}

// Installed describes a completed swap.
type Installed struct {
	Tag      string
	Previous string // path of the backup <exe>.old; empty when the same version was reinstalled
}

// Install downloads the release's binary for this platform, verifies it and
// replaces the file at exe with it.
func (c *Client) Install(ctx context.Context, rel *Release, exe string) (*Installed, error) {
	name := AssetName()
	bin, ok := rel.asset(name)
	if !ok {
		return nil, fmt.Errorf("release %s has no %s binary", rel.Tag, name)
	}
	sums, ok := rel.asset(ChecksumsAsset)
	if !ok {
		return nil, fmt.Errorf("release %s has no %s; refusing to install an unverified binary", rel.Tag, ChecksumsAsset)
	}

	resp, err := c.download(ctx, sums)
	if err != nil {
		return nil, err
	}
	want, err := parseChecksums(io.LimitReader(resp.Body, 1<<20), name)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	// Download next to the target so the final rename stays on one filesystem.
	tmp := exe + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return nil, fmt.Errorf("cannot write next to %s (run as root?): %w", exe, err)
	}
	cleanup := func() { f.Close(); os.Remove(tmp) }

	resp, err = c.download(ctx, bin)
	if err != nil {
		cleanup()
		return nil, err
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxBinaryBytes+1))
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("downloading %s: %w", name, err)
	}
	if n > maxBinaryBytes {
		cleanup()
		return nil, errors.New("download is unreasonably large; refusing it")
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(tmp)
		return nil, fmt.Errorf("checksum mismatch for %s: download is %s, release says %s", name, got, want)
	}

	// The binary must run on this machine and identify itself as the release.
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, tmp, "version").Output()
	if err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("the downloaded binary does not run here: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != rel.Tag {
		os.Remove(tmp)
		return nil, fmt.Errorf("the downloaded binary reports version %q, expected %q", got, rel.Tag)
	}

	// Reinstalling the version that is already there must not overwrite the
	// backup of the version before it.
	if binaryVersion(ctx, exe) == rel.Tag {
		if err := os.Rename(tmp, exe); err != nil {
			os.Remove(tmp)
			return nil, err
		}
		return &Installed{Tag: rel.Tag}, nil
	}
	old := exe + ".old"
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("keeping the previous binary: %w", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Rename(old, exe) // put it back
		os.Remove(tmp)
		return nil, err
	}
	return &Installed{Tag: rel.Tag, Previous: old}, nil
}

// binaryVersion asks a binary for its version ("" if it can't say).
func binaryVersion(ctx context.Context, path string) string {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, path, "version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Rollback swaps the previous binary (<exe>.old) back in.
func Rollback(exe string) error {
	old := exe + ".old"
	if _, err := os.Stat(old); err != nil {
		return fmt.Errorf("no previous version to go back to (%s is missing)", old)
	}
	swap := exe + ".swap"
	if err := os.Rename(exe, swap); err != nil {
		return err
	}
	if err := os.Rename(old, exe); err != nil {
		_ = os.Rename(swap, exe)
		return err
	}
	return os.Rename(swap, old) // so rolling back twice returns to the newer one
}

// Executable is the real path of the running binary, symlinks resolved.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, nil
}

// UnderSystemd reports whether this process was started by systemd.
func UnderSystemd() bool { return os.Getenv("INVOCATION_ID") != "" }

// RestartService restarts the systemd unit. With noBlock it only queues the
// restart and returns, which is what a service restarting itself needs.
func RestartService(name string, noBlock bool) error {
	args := []string{"restart"}
	if noBlock {
		args = append(args, "--no-block")
	}
	out, err := exec.Command("systemctl", append(args, name)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
