// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/veldmesh/veld/internal/acl"
	"github.com/veldmesh/veld/internal/config"
	"github.com/veldmesh/veld/internal/daemon"
	"github.com/veldmesh/veld/internal/daemon/ipctypes"
	"github.com/veldmesh/veld/internal/tofu"
)

var (
	socketPath string
	version    = "dev" // overridden by -ldflags "-X main.version=..."
)

// printer wraps a writer and keeps the first write error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) Write(b []byte) (int, error) {
	if p.err != nil {
		return len(b), nil // swallow writes after error
	}
	n, err := p.w.Write(b)
	if err != nil {
		p.err = err
	}
	return n, err
}

func (p *printer) Printf(format string, args ...any) {
	_, _ = fmt.Fprintf(p, format, args...)
}

func (p *printer) Println(args ...any) {
	_, _ = fmt.Fprintln(p, args...)
}

func (p *printer) Err() error {
	return p.err
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "veld",
	Short: "Veld mesh VPN",
	Long:  "Veld: encrypted mesh VPN with peer discovery",
}

func init() {
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "", "IPC socket path (default: platform default)")
	rootCmd.AddCommand(upCmd, downCmd, statusCmd, loginCmd, joinCmd, versionCmd, tofuCmd, policyCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), version)
	},
}

// --- UP command ---

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Start the daemon",
	RunE:  runUp,
}

var (
	upConfigPath string
	upForeground bool
)

func init() {
	upCmd.Flags().StringVar(&upConfigPath, "config", "", "config file path (default: ~/.config/veld/config.toml)")
	upCmd.Flags().BoolVar(&upForeground, "foreground", false, "run in foreground (don't daemonize)")
}

func runUp(cobraCmd *cobra.Command, args []string) error {
	sock := getSocketPath()

	// Check if daemon is already running
	if isRunning(sock) {
		st, err := getStatus(sock)
		if err == nil {
			_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "daemon already running\n")
			_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  VPN Address: %s\n", st.VPNAddr)
			_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  Peer ID: %s\n", st.PeerID)
			_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  Network: %s\n", st.NetworkID)
			_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  Peers: %d\n", len(st.Peers))
			return nil
		}
	}

	// Load config
	cfg, err := loadConfig(upConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintln(cobraCmd.OutOrStdout(), "no config found — run 'veld login' to get started")
			return nil
		}
		return err
	}
	if cfg.Coord.Addr != "" && cfg.Coord.Token == "" {
		_, _ = fmt.Fprintln(cobraCmd.OutOrStdout(), "not logged in — run 'veld login' to authenticate")
		return nil
	}

	if upForeground {
		// Run daemon in foreground
		d, err := daemon.NewFromConfig(cfg)
		if err != nil {
			return fmt.Errorf("create daemon: %w", err)
		}

		d.Start()
		defer d.Stop()

		// Handle signals
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			d.Stop()
		}()

		d.Wait()
		return nil
	}

	// Background mode: spawn daemon process
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}

	daemonPath := filepath.Join(filepath.Dir(exePath), "veld-daemon")
	if _, err := os.Stat(daemonPath); err != nil {
		daemonPath = "veld-daemon" // try from PATH
	}

	// Pass the config this command loaded: the daemon's own default path
	// is not the CLI's.
	cfgPath, err := getConfigPath(upConfigPath)
	if err != nil {
		return err
	}
	cmdArgs := []string{"--config", cfgPath}
	if socketPath != "" {
		cmdArgs = append(cmdArgs, "--socket", socketPath)
	}

	daemonCmd := exec.Command(daemonPath, cmdArgs...)
	daemonCmd.Stdout = os.Stdout
	daemonCmd.Stderr = os.Stderr

	if err := daemonCmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	// Release the process (don't wait for it)
	_ = daemonCmd.Process.Release()

	// Poll until daemon is running
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if isRunning(sock) {
			st, _ := getStatus(sock)
			if st != nil {
				_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "daemon started\n")
				_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  VPN Address: %s\n", st.VPNAddr)
				_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  Network: %s\n", st.NetworkID)
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "daemon may still be starting; use 'veld status' to check\n")
	return nil
}

// --- DOWN command ---

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop the running daemon",
	RunE:  runDown,
}

func runDown(cobraCmd *cobra.Command, args []string) error {
	sock := getSocketPath()

	if !isRunning(sock) {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "daemon not running\n")
		return nil
	}

	// Send shutdown request
	if err := ipcPost(sock, "/api/shutdown"); err != nil {
		return fmt.Errorf("shutdown request failed: %w", err)
	}

	// Wait for socket to disappear
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !isRunning(sock) {
			_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "daemon stopped\n")
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "daemon shutdown timeout\n")
	return nil
}

// --- STATUS command ---

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status",
	RunE:  runStatus,
}

func runStatus(cobraCmd *cobra.Command, args []string) error {
	sock := getSocketPath()

	if !isRunning(sock) {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "daemon not running\n")
		return nil
	}

	st, err := getStatus(sock)
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	if st == nil {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "daemon not responding\n")
		return nil
	}

	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "Daemon Status:\n")
	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  Running: %v\n", st.Running)
	if st.VPNAddr != "" {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  VPN Address: %s\n", st.VPNAddr)
	}
	if st.PeerID != "" {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  Peer ID: %s\n", st.PeerID)
	}
	if st.NetworkID != "" {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  Network: %s\n", st.NetworkID)
	}
	if st.CoordAddr != "" {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  Coordinator: %s\n", st.CoordAddr)
	}
	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  Peers (%d):\n", len(st.Peers))
	for _, p := range st.Peers {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "    %s (%s)\n", p.VPNAddr, p.State)
		if p.Endpoint != "" {
			_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "      Endpoint: %s\n", p.Endpoint)
		}
	}

	return nil
}

// --- LOGIN command ---

const (
	cliAuthPageURL     = "https://app.veldmesh.io/cli-auth"
	cliAuthExchangeURL = "https://api.veldmesh.io/v1/cli-auth"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the coordinator",
	RunE:  runLogin,
}

var (
	loginServer     string
	loginNetworkID  string
	loginToken      string
	loginConfigPath string
)

func init() {
	loginCmd.Flags().StringVar(&loginServer, "server", "", "coordinator server address")
	loginCmd.Flags().StringVar(&loginNetworkID, "network-id", "", "network ID")
	loginCmd.Flags().StringVar(&loginToken, "token", "", `auth token; "-" reads it from stdin (default: $VELD_TOKEN)`)
	loginCmd.Flags().StringVar(&loginConfigPath, "config", "", "config file path")
}

func runLogin(cobraCmd *cobra.Command, args []string) error {
	cfgPath, err := getConfigPath(loginConfigPath)
	if err != nil {
		return err
	}

	if loginServer != "" {
		// A self-hosted coordinator: never fall back to the hosted
		// browser flow, which would ignore --server.
		token, err := resolveToken(loginToken)
		if err != nil {
			return err
		}
		if token == "" {
			return errors.New(`--server needs a token: pass --token - to read it from stdin, or set VELD_TOKEN`)
		}
		return saveCredentials(cobraCmd, loginServer, loginNetworkID, token, cfgPath)
	}

	return runBrowserAuthFlow(cobraCmd, cfgPath)
}

// resolveToken returns the token to use: flag "-" reads one line from stdin,
// an empty flag falls back to $VELD_TOKEN. Tokens given on the command line
// are visible to other local users in the process list and end up in shell
// history, so the flag value itself is best avoided.
func resolveToken(flagValue string) (string, error) {
	switch flagValue {
	case "-":
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read token from stdin: %w", err)
		}
		return strings.TrimSpace(line), nil
	case "":
		return os.Getenv("VELD_TOKEN"), nil
	default:
		return flagValue, nil
	}
}

func saveCredentials(cobraCmd *cobra.Command, server, networkID, token, cfgPath string) error {
	cfg, err := loadConfigOrNew(cfgPath)
	if err != nil {
		return err
	}

	cfg.Coord.Addr = server
	cfg.Coord.NetworkID = networkID
	cfg.Coord.Token = token

	if err := writeConfig(cfgPath, cfg); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "Logged in. Credentials saved to %s\n", cfgPath)
	return nil
}

func runBrowserAuthFlow(cobraCmd *cobra.Command, cfgPath string) error {
	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "Opening %s in your browser...\n", cliAuthPageURL)
	openBrowserURL(cliAuthPageURL)

	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "Enter auth code: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	code := strings.TrimSpace(scanner.Text())
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read auth code: %w", err)
	}

	server, networkID, token, err := exchangeCliAuthCode(code)
	if err != nil {
		return err
	}

	return saveCredentials(cobraCmd, server, networkID, token, cfgPath)
}

func openBrowserURL(rawURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", rawURL)
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		return
	}
	_ = cmd.Start()
}

func exchangeCliAuthCode(code string) (server, networkID, token string, err error) {
	client := &http.Client{Timeout: 10 * time.Second}

	reqURL := cliAuthExchangeURL + "?code=" + url.QueryEscape(strings.ToUpper(strings.TrimSpace(code)))
	resp, err := client.Get(reqURL)
	if err != nil {
		return "", "", "", fmt.Errorf("auth exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", "", "", fmt.Errorf("auth exchange failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		Token     string `json:"token"`
		NetworkID string `json:"network_id"`
		CoordAddr string `json:"coord_addr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", fmt.Errorf("auth exchange: invalid response: %w", err)
	}

	return result.CoordAddr, result.NetworkID, result.Token, nil
}

// --- JOIN command ---

var joinCmd = &cobra.Command{
	Use:   "join <token>",
	Short: `Join a network using a token ("-" reads it from stdin)`,
	Args:  cobra.ExactArgs(1),
	RunE:  runJoin,
}

var (
	joinServer     string
	joinNetworkID  string
	joinConfigPath string
)

func init() {
	joinCmd.Flags().StringVar(&joinServer, "server", "", "coordinator server address (default: infer from token)")
	joinCmd.Flags().StringVar(&joinNetworkID, "network-id", "", "network ID (default: infer from token)")
	joinCmd.Flags().StringVar(&joinConfigPath, "config", "", "config file path")
}

func runJoin(cobraCmd *cobra.Command, args []string) error {
	token, err := resolveToken(args[0])
	if err != nil {
		return err
	}
	cfgPath, err := getConfigPath(joinConfigPath)
	if err != nil {
		return err
	}

	cfg, err := loadConfigOrNew(cfgPath)
	if err != nil {
		return err
	}

	cfg.Coord.Token = token
	if joinServer != "" {
		cfg.Coord.Addr = joinServer
	}
	if joinNetworkID != "" {
		cfg.Coord.NetworkID = joinNetworkID
	}

	if err := writeConfig(cfgPath, cfg); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "saved token to %s\n", cfgPath)
	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "use 'veld up' to connect\n")
	return nil
}

// --- TOFU command ---

var tofuCmd = &cobra.Command{
	Use:   "tofu",
	Short: "Manage TOFU (Trust-On-First-Use) fingerprint pins",
	Long:  "Manage TOFU fingerprint pins. Pins are keyed by Ed25519 public key with a reverse VPN address map.",
}

var tofuConfigPath string

func init() {
	tofuCmd.PersistentFlags().StringVar(&tofuConfigPath, "config", "", "config file path (default: ~/.config/veld/config.toml)")
	tofuCmd.AddCommand(tofuListCmd, tofuForgetCmd)
}

var tofuListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all pinned fingerprints",
	RunE:  runTofuList,
}

func runTofuList(cobraCmd *cobra.Command, args []string) error {
	tofuStore, err := openTofuStore()
	if err != nil {
		return err
	}

	pins := tofuStore.List()
	if len(pins) == 0 {
		_, _ = fmt.Fprintln(cobraCmd.OutOrStdout(), "no pinned fingerprints")
		return nil
	}

	_, _ = fmt.Fprintln(cobraCmd.OutOrStdout(), "Pinned fingerprints (VPN address → SHA-256 fingerprint):")
	for vpnAddr, fp := range pins {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "  %s → %s\n", vpnAddr, fp)
	}
	return nil
}

var tofuForgetCmd = &cobra.Command{
	Use:   "forget <peer>",
	Short: "Forget a pinned fingerprint for a peer",
	Long: `Forget a pinned fingerprint for a peer. The peer is specified as a
VPN address (IP). The next handshake with that peer will re-pin their fingerprint.`,
	Args: cobra.ExactArgs(1),
	RunE: runTofuForget,
}

func runTofuForget(cobraCmd *cobra.Command, args []string) error {
	peerArg := args[0]

	// The peer must be a VPN address.
	if _, err := netip.ParseAddr(peerArg); err != nil {
		return fmt.Errorf("invalid peer argument %q: must be a VPN address (e.g. 10.0.0.2)", peerArg)
	}

	tofuStore, err := openTofuStore()
	if err != nil {
		return err
	}

	if err := tofuStore.ForgetByVPNAddr(peerArg); err != nil {
		return fmt.Errorf("forget: %w", err)
	}
	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "forgot pin for peer %s\n", peerArg)
	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "the next handshake with this peer will re-pin their fingerprint\n")
	return nil
}

// openTofuStore loads the config to find the identity path, then opens the
// TOFU store that lives next to it.
func openTofuStore() (*tofu.Store, error) {
	cfgPath, err := getConfigPath(tofuConfigPath)
	if err != nil {
		return nil, err
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load config: %w", err)
	}
	var identityPath string
	if cfg != nil {
		identityPath = cfg.Node.IdentityPath
	} else {
		identityPath = filepath.Join(filepath.Dir(cfgPath), "identity.json")
	}
	tofuPath := filepath.Join(filepath.Dir(identityPath), "tofu.json")

	store, err := tofu.New(tofuPath)
	if err != nil {
		return nil, fmt.Errorf("load TOFU store: %w", err)
	}
	return store, nil
}

// --- POLICY command ---

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage ACL policies",
	Long:  "Validate, test, sign, push, and inspect ACL policies.",
}

var (
	policyConfigPath string
)

func init() {
	policyCmd.PersistentFlags().StringVar(&policyConfigPath, "config", "", "config file path (default: ~/.config/veld/config.toml)")
	policyCmd.AddCommand(policyCheckCmd, policyTestCmd, policyStatusCmd, policyKeygenCmd, policySignCmd, policyPushCmd, policyReloadCmd)
}

// --- POLICY CHECK command ---

var policyCheckCmd = &cobra.Command{
	Use:   "check <policy.toml>",
	Short: "Validate a policy file",
	Long: `Validate a policy file's syntax, resolve names/tags to IDs,
and print warnings for unmatchable rules or unknown names.
Exits with non-zero on errors.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyCheck,
}

func runPolicyCheck(cobraCmd *cobra.Command, args []string) error {
	policyPath := args[0]

	data, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	p, warnings, err := acl.ParsePolicy(string(data))
	if err != nil {
		_, _ = fmt.Fprintf(cobraCmd.ErrOrStderr(), "policy: %v\n", err)
		return err
	}

	// Print warnings
	for _, w := range warnings {
		_, _ = fmt.Fprintf(cobraCmd.ErrOrStderr(), "warning: %s\n", w)
	}

	// Print resolved policy summary
	out := &printer{w: cobraCmd.OutOrStdout()}
	out.Printf("Policy OK (version %d)\n", p.Version)
	out.Printf("  Default: %s\n", p.Default)
	out.Printf("  Peers (%d):\n", len(p.Peers))
	for name, key := range p.Peers {
		out.Printf("    %s: %s\n", name, formatPeerKey(key))
	}
	if len(p.Tags) > 0 {
		out.Printf("  Tags (%d):\n", len(p.Tags))
		for tag, peers := range p.Tags {
			out.Printf("    %s: %s\n", tag, strings.Join(peers, ", "))
		}
	}
	out.Printf("  Rules (%d):\n", len(p.Rules))
	for i, rule := range p.Rules {
		ports := make([]string, len(rule.Ports))
		for j, pr := range rule.Ports {
			ports[j] = formatPortRange(pr)
		}
		out.Printf("    [%d] from=%s to=%s ports=%s\n", i, rule.From, rule.To, strings.Join(ports, ", "))
	}
	if len(p.OutboundOnly) > 0 {
		out.Printf("  Outbound-only peers: %s\n", strings.Join(p.OutboundOnly, ", "))
	}

	return out.Err()
}

// --- POLICY TEST command ---

var policyTestCmd = &cobra.Command{
	Use:   "test <policy.toml> <from> <to> <proto/port>",
	Short: "Test a policy decision",
	Long: `Test a policy decision against a policy file.
<from> and <to> accept peer names or Ed25519 public key IDs (32-byte hex).
Wildcards (*) and tags (tag:...) are not supported for from/to; use specific peer names or IDs.
<proto/port> examples: tcp/22, udp/53, icmp, *.
For port ranges like tcp/8000-8099, only the first port (8000) is tested.
When "icmp" is specified, both ICMPv4 and ICMPv6 are tested against the policy.
Prints allow/deny and which rule (or default) decided.
Honours outbound_only.`,
	Args: cobra.ExactArgs(4),
	RunE: runPolicyTest,
}

func runPolicyTest(cobraCmd *cobra.Command, args []string) error {
	policyPath := args[0]
	fromArg := args[1]
	toArg := args[2]
	protoPort := args[3]

	data, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	p, warnings, err := acl.ParsePolicy(string(data))
	if err != nil {
		_, _ = fmt.Fprintf(cobraCmd.ErrOrStderr(), "policy: %v\n", err)
		return err
	}

	// Print warnings
	for _, w := range warnings {
		_, _ = fmt.Fprintf(cobraCmd.ErrOrStderr(), "warning: %s\n", w)
	}

	// Resolve from/to to peer keys
	fromKey, err := resolveSubjectKey(fromArg, p)
	if err != nil {
		return fmt.Errorf("from: %w", err)
	}
	toKey, err := resolveSubjectKey(toArg, p)
	if err != nil {
		return fmt.Errorf("to: %w", err)
	}

	// Parse proto/port
	protos, port, isPortRange, err := parseProtoPort(protoPort)
	if err != nil {
		return fmt.Errorf("proto/port: %w", err)
	}

	if isPortRange {
		_, _ = fmt.Fprintf(cobraCmd.ErrOrStderr(), "warning: port range specified; only the first port (%d) is tested\n", port)
	}

	// Compile and decide
	cp := p.Compile()

	finalAction := acl.ActionDeny
	finalRuleIdx := -1
	var finalOutboundOnly bool

	for _, proto := range protos {
		dec := cp.Decide(fromKey, toKey, proto, port)

		// If any proto allows, the result is allow (unless outbound-only)
		if dec.Action == acl.ActionAllow {
			finalAction = acl.ActionAllow
			if dec.RuleIndex >= 0 {
				finalRuleIdx = dec.RuleIndex
			} else {
				finalRuleIdx = -1
			}
			finalOutboundOnly = dec.OutboundOnly
			// Allow short-circuits (unless we want to check if any proto is outbound-only)
		} else if finalAction == acl.ActionDeny && dec.OutboundOnly {
			finalOutboundOnly = true
		}
	}

	// Print result
	out := &printer{w: cobraCmd.OutOrStdout()}
	actionStr := "ALLOW"
	if finalAction == acl.ActionDeny {
		actionStr = "DENY"
	}
	out.Printf("%s\n", actionStr)

	if finalOutboundOnly {
		out.Printf("  (outbound-only denial)\n")
	}

	if finalRuleIdx >= 0 {
		rule := p.Rules[finalRuleIdx]
		ports := make([]string, len(rule.Ports))
		for j, pr := range rule.Ports {
			ports[j] = formatPortRange(pr)
		}
		out.Printf("  Matched rule %d: from=%s to=%s ports=%s\n", finalRuleIdx, rule.From, rule.To, strings.Join(ports, ", "))
	} else {
		out.Printf("  Default action: %s\n", p.Default)
	}

	return out.Err()
}

// --- POLICY STATUS command ---

var policyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active policy status from daemon",
	Long: `Show the active local policy path and hash, network policy version/signer/age,
drop counters per peer and rule, and the last N drops. When using coordinator mode,
also shows if the coordinator's version differs from the locally enforced version
(stale peer visible).`,
	RunE: runPolicyStatus,
}

func runPolicyStatus(cobraCmd *cobra.Command, args []string) error {
	sock := getSocketPath()

	if !isRunning(sock) {
		_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "daemon not running\n")
		return nil
	}

	client := newSocketClient(sock)
	resp, err := client.Get("http://daemon/api/policy/status")
	if err != nil {
		return fmt.Errorf("get policy status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("policy status failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result ipctypes.PolicyStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	out := &printer{w: cobraCmd.OutOrStdout()}

	// Print local policy info
	out.Printf("Local Policy:\n")
	if result.LocalPolicy.Path != "" {
		out.Printf("  Path: %s\n", result.LocalPolicy.Path)
		out.Printf("  Hash: %s\n", result.LocalPolicy.Hash)
		out.Printf("  Version: %d\n", result.LocalPolicy.Version)
		out.Printf("  Default: %s\n", result.LocalPolicy.Default)
		out.Printf("  Rules: %d\n", result.LocalPolicy.Rules)
	} else {
		out.Printf("  (none)\n")
	}

	// Print network policy info
	out.Printf("\nNetwork Policy:\n")
	if result.NetworkPolicy.Version > 0 {
		out.Printf("  Version: %d\n", result.NetworkPolicy.Version)
		if result.NetworkPolicy.Signer != "" {
			out.Printf("  Signer: %s\n", result.NetworkPolicy.Signer)
		}
		if result.NetworkPolicy.Age != "" {
			out.Printf("  Age: %s\n", result.NetworkPolicy.Age)
		}
		if result.NetworkPolicy.CoordinatorVersion > 0 {
			syncStatus := "synced"
			if result.NetworkPolicy.CoordinatorVersion != result.NetworkPolicy.Version {
				syncStatus = "STALE (coordinator has newer version)"
			}
			out.Printf("  Coordinator Version: %d (%s)\n", result.NetworkPolicy.CoordinatorVersion, syncStatus)
		}
	} else {
		out.Printf("  (none)\n")
	}

	// Print drop counters
	out.Printf("\nDrop Counters:\n")
	if len(result.DropCounters.ByPeer) > 0 {
		out.Printf("  By Peer:\n")
		for peerID, count := range result.DropCounters.ByPeer {
			out.Printf("    %s: %d\n", peerID, count)
		}
	} else {
		out.Printf("  By Peer: (none)\n")
	}
	if len(result.DropCounters.ByRule) > 0 {
		out.Printf("  By Rule:\n")
		for ruleIdx, count := range result.DropCounters.ByRule {
			out.Printf("    rule %d: %d\n", ruleIdx, count)
		}
	} else {
		out.Printf("  By Rule: (none)\n")
	}
	if len(result.DropCounters.ByOutboundOnly) > 0 {
		out.Printf("  By Outbound-Only:\n")
		for peerID, count := range result.DropCounters.ByOutboundOnly {
			out.Printf("    %s: %d\n", peerID, count)
		}
	} else {
		out.Printf("  By Outbound-Only: (none)\n")
	}

	// Print recent drops
	out.Printf("\nRecent Drops (last %d):\n", len(result.RecentDrops))
	if len(result.RecentDrops) == 0 {
		out.Printf("  (none)\n")
	} else {
		for _, drop := range result.RecentDrops {
			out.Printf("  %s  peer=%s  proto=%s  port=%d  rule=%s\n",
				drop.Time.Format(time.RFC3339),
				drop.PeerID,
				drop.Proto,
				drop.Port,
				ruleIdxToString(drop.RuleIdx),
			)
		}
	}

	return out.Err()
}

func ruleIdxToString(idx int) string {
	switch idx {
	case -1:
		return "default"
	default:
		return fmt.Sprintf("rule %d", idx)
	}
}

// --- POLICY KEYGEN command ---

var policyKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an admin key pair for signing network policies",
	Long: `Generate an Ed25519 key pair for signing network policies.
This key is separate from node keys and should be kept secure (offline if possible).
The private key is written to a file with 0600 permissions.
The public key is printed to stdout.`,
	RunE: runPolicyKeygen,
}

var (
	policyKeygenOut string
)

func init() {
	policyKeygenCmd.Flags().StringVar(&policyKeygenOut, "out", "admin.key", "output file for private key")
}

func runPolicyKeygen(cobraCmd *cobra.Command, args []string) error {
	privKey, pubKey, err := acl.GenerateAdminKey()
	if err != nil {
		return fmt.Errorf("generate admin key: %w", err)
	}

	// Write private key to file
	if err := acl.WriteAdminKeyFile(policyKeygenOut, privKey); err != nil {
		return fmt.Errorf("write admin key: %w", err)
	}

	// Print public key
	encodedPub := base64.StdEncoding.EncodeToString(pubKey)
	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "ed25519:%s\n", encodedPub)
	_, _ = fmt.Fprintf(cobraCmd.ErrOrStderr(), "Private key written to %s (0600)\n", policyKeygenOut)
	_, _ = fmt.Fprintf(cobraCmd.ErrOrStderr(), "Keep this key secure! It is used to sign network policies.\n")

	return nil
}

// --- POLICY SIGN command ---

var policySignCmd = &cobra.Command{
	Use:   "sign <policy.toml>",
	Short: "Sign a policy file with an admin key",
	Long: `Sign a policy TOML file with an admin private key, producing a signed network policy envelope.
The envelope includes the canonical policy, version, signer public key, and Ed25519 signature.
Refuses to overwrite an existing output file if its version is >= the new policy's version.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicySign,
}

var (
	policySignKey string
	policySignOut string
)

func init() {
	policySignCmd.Flags().StringVar(&policySignKey, "key", "", "admin private key file (required)")
	policySignCmd.Flags().StringVar(&policySignOut, "out", "policy.signed", "output file for signed policy")
	_ = policySignCmd.MarkFlagRequired("key")
}

func runPolicySign(cobraCmd *cobra.Command, args []string) error {
	policyPath := args[0]

	// Read policy TOML
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	// Read admin private key
	privKey, err := acl.ReadAdminKeyFile(policySignKey)
	if err != nil {
		return fmt.Errorf("read admin key: %w", err)
	}

	// Sign the policy
	envelope, err := acl.SignPolicy(string(policyData), privKey)
	if err != nil {
		return fmt.Errorf("sign policy: %w", err)
	}

	// Parse to get version for write check
	p, _, err := acl.ParsePolicy(string(policyData))
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}

	// Write signed policy envelope
	if err := acl.WriteNetworkPolicyFile(policySignOut, envelope, p.Version); err != nil {
		return fmt.Errorf("write signed policy: %w", err)
	}

	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "Signed policy written to %s (version %d)\n", policySignOut, p.Version)
	return nil
}

// --- POLICY PUSH command ---

var policyPushCmd = &cobra.Command{
	Use:   "push <policy.signed>",
	Short: "Push a signed network policy to the coordinator",
	Long: `Push a signed network policy envelope to the coordinator.
The coordinator verifies the envelope header, checks the size cap (256 KiB)
and version monotonicity, stores it, and distributes it to all peers in
the network via the Watch stream. Requires the daemon to be running and
connected to a coordinator.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyPush,
}

func runPolicyPush(cobraCmd *cobra.Command, args []string) error {
	policyPath := args[0]

	sock := getSocketPath()

	if !isRunning(sock) {
		return fmt.Errorf("daemon not running")
	}

	// Read the signed policy envelope
	envelope, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	if len(envelope) == 0 {
		return fmt.Errorf("empty policy envelope")
	}

	client := newSocketClient(sock)
	resp, err := client.Post("http://daemon/api/policy/push", "application/octet-stream", strings.NewReader(string(envelope)))
	if err != nil {
		return fmt.Errorf("push request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		Version int `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "network policy pushed (version %d)\n", result.Version)
	return nil
}

// --- POLICY RELOAD command ---

var policyReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload the network policy from disk via daemon IPC",
	Long: `Triggers the running daemon to reload the network policy file.
Requires the daemon to be running with a network policy configured.`,
	RunE: runPolicyReload,
}

func runPolicyReload(cobraCmd *cobra.Command, args []string) error {
	sock := getSocketPath()

	if !isRunning(sock) {
		return fmt.Errorf("daemon not running")
	}

	client := newSocketClient(sock)
	resp, err := client.Post("http://daemon/api/policy/reload-network", "application/json", nil)
	if err != nil {
		return fmt.Errorf("reload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reload failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	_, _ = fmt.Fprintf(cobraCmd.OutOrStdout(), "network policy reloaded\n")
	return nil
}

// --- Helpers ---

func getSocketPath() string {
	if socketPath != "" {
		return socketPath
	}
	return config.DefaultSocketPath()
}

func getConfigPath(cfgPath string) (string, error) {
	if cfgPath != "" {
		return cfgPath, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "veld", "config.toml"), nil
}

func loadConfig(cfgPath string) (*config.Config, error) {
	path := cfgPath
	if path == "" {
		var err error
		path, err = getConfigPath("")
		if err != nil {
			return nil, fmt.Errorf("get config path: %w", err)
		}
	}

	cfg, err := config.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load config %q: %w", path, err)
	}
	return cfg, nil
}

func loadConfigOrNew(cfgPath string) (*config.Config, error) {
	path := cfgPath
	if path == "" {
		var err error
		path, err = getConfigPath("")
		if err != nil {
			return nil, err
		}
	}

	cfg, err := config.LoadFile(path)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		cfg = &config.Config{
			Node: config.NodeConfig{
				IdentityPath: filepath.Join(filepath.Dir(path), "identity.json"),
				ListenAddr:   "0.0.0.0:51820",
				IfaceName:    "",
				MTU:          1420,
			},
			Coord: config.CoordConfig{
				Addr: config.DefaultCoordAddr,
			},
		}
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

func writeConfig(path string, cfg *config.Config) (err error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	// The config holds the coordinator token. New files are owner-only; an
	// existing file keeps its owner and group (a daemon user may read it
	// through its group) but never stays readable by everyone.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o007 != 0 {
		if err := f.Chmod(perm &^ 0o007); err != nil {
			return err
		}
	}

	return toml.NewEncoder(f).Encode(cfg)
}

func newSocketClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}
}

func isRunning(sock string) bool {
	client := newSocketClient(sock)
	resp, err := client.Get("http://daemon/api/status")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func getStatus(sock string) (*daemon.StatusResponse, error) {
	client := newSocketClient(sock)
	resp, err := client.Get("http://daemon/api/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	var st daemon.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

func ipcPost(sock string, path string) error {
	client := newSocketClient(sock)
	resp, err := client.Post("http://daemon"+path, "application/json", nil)
	if err != nil {
		return err
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	return nil
}

func formatPeerKey(key acl.PeerKey) string {
	return "ed25519:" + hex.EncodeToString(key[:])
}

func formatPortRange(pr acl.PortRange) string {
	if pr.Proto == acl.ProtoAny {
		return "*"
	}
	if pr.Proto == acl.ProtoICMP && pr.MatchesICMPv6() {
		return "icmp"
	}
	var protoStr string
	switch pr.Proto {
	case acl.ProtoTCP:
		protoStr = "tcp"
	case acl.ProtoUDP:
		protoStr = "udp"
	case acl.ProtoICMP:
		protoStr = "icmp"
	case acl.ProtoICMPv6:
		protoStr = "icmpv6"
	default:
		protoStr = fmt.Sprintf("proto%d", pr.Proto)
	}
	if pr.Start == 0 && pr.End == 65535 {
		return protoStr + "/*"
	}
	if pr.Start == pr.End {
		return fmt.Sprintf("%s/%d", protoStr, pr.Start)
	}
	return fmt.Sprintf("%s/%d-%d", protoStr, pr.Start, pr.End)
}

func resolveSubjectKey(arg string, p *acl.Policy) (acl.PeerKey, error) {
	// Check if it's a hex-encoded Ed25519 public key (64 hex chars = 32 bytes)
	if len(arg) == 64 {
		if _, err := hex.DecodeString(arg); err == nil {
			var key acl.PeerKey
			decoded, _ := hex.DecodeString(arg)
			copy(key[:], decoded)
			return key, nil
		}
	}

	// Check if it's a base64-encoded Ed25519 public key
	if strings.HasPrefix(arg, "ed25519:") {
		encoded := arg[len("ed25519:"):]
		if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			if len(decoded) == 32 {
				var key acl.PeerKey
				copy(key[:], decoded)
				return key, nil
			}
		}
	}

	// Try as peer name
	if arg == "*" {
		return acl.PeerKey{}, errors.New("wildcard '*' not supported for test from/to; use a specific peer name or ID")
	}

	if strings.HasPrefix(arg, "tag:") {
		return acl.PeerKey{}, errors.New("tag not supported for test from/to; use a specific peer name or ID")
	}

	// Look up by peer name
	if key, ok := p.Peers[arg]; ok {
		return key, nil
	}

	// Not found
	return acl.PeerKey{}, fmt.Errorf("unknown peer or ID: %q", arg)
}

// parseProtoPort parses a proto/port string and returns the protocol(s) to test,
// the port, whether it was a port range, and any error.
// For "icmp", returns both ICMPv4 and ICMPv6 to test.
// For port ranges, returns the first port and isPortRange=true.
func parseProtoPort(s string) ([]acl.Proto, uint16, bool, error) {
	if s == "*" {
		return []acl.Proto{acl.ProtoAny}, 0, false, nil
	}
	if strings.EqualFold(s, "icmp") {
		// "icmp" keyword matches both ICMPv4 and ICMPv6 in policy
		return []acl.Proto{acl.ProtoICMP, acl.ProtoICMPv6}, 0, false, nil
	}

	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return nil, 0, false, fmt.Errorf("invalid format: %q (expected proto/port or proto/start-end)", s)
	}

	protoStr := strings.ToLower(parts[0])
	portStr := parts[1]

	var proto acl.Proto
	switch protoStr {
	case "tcp":
		proto = acl.ProtoTCP
	case "udp":
		proto = acl.ProtoUDP
	case "icmp":
		// Explicit "icmp" without range still matches both
		return []acl.Proto{acl.ProtoICMP, acl.ProtoICMPv6}, 0, false, nil
	default:
		return nil, 0, false, fmt.Errorf("unknown protocol: %q", protoStr)
	}

	// Parse port or range (for testing, only the first port of a range is used)
	if strings.Contains(portStr, "-") {
		rangeParts := strings.Split(portStr, "-")
		if len(rangeParts) != 2 {
			return nil, 0, false, fmt.Errorf("invalid port range: %q", portStr)
		}
		start, err := parsePort(rangeParts[0])
		if err != nil {
			return nil, 0, false, err
		}
		return []acl.Proto{proto}, start, true, nil
	}

	port, err := parsePort(portStr)
	if err != nil {
		return nil, 0, false, err
	}
	return []acl.Proto{proto}, port, false, nil
}

func parsePort(s string) (uint16, error) {
	var port uint64
	_, err := fmt.Sscanf(s, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %q", s)
	}
	if port > 65535 {
		return 0, fmt.Errorf("port %d exceeds maximum 65535", port)
	}
	return uint16(port), nil
}
