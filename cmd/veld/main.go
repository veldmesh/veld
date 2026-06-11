// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

	"github.com/veldmesh/veld/internal/config"
	"github.com/veldmesh/veld/internal/daemon"
)

var (
	socketPath string
	version    = "dev" // overridden by -ldflags "-X main.version=..."
)

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
	rootCmd.AddCommand(upCmd, downCmd, statusCmd, loginCmd, joinCmd, versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}

// --- UP command ---

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Start the daemon",
	RunE:  runUp,
}

var (
	upConfigPath  string
	upForeground  bool
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
			fmt.Printf("daemon already running\n")
			fmt.Printf("  VPN Address: %s\n", st.VPNAddr)
			fmt.Printf("  Peer ID: %s\n", st.PeerID)
			fmt.Printf("  Network: %s\n", st.NetworkID)
			fmt.Printf("  Peers: %d\n", len(st.Peers))
			return nil
		}
	}

	// Load config
	cfg, err := loadConfig(upConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("no config found — run 'veld login' to get started")
			return nil
		}
		return err
	}
	if cfg.Coord.Addr != "" && cfg.Coord.Token == "" {
		fmt.Println("not logged in — run 'veld login' to authenticate")
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

	cmdArgs := []string{"--config", upConfigPath}
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
	daemonCmd.Process.Release()

	// Poll until daemon is running
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if isRunning(sock) {
			st, _ := getStatus(sock)
			if st != nil {
				fmt.Printf("daemon started\n")
				fmt.Printf("  VPN Address: %s\n", st.VPNAddr)
				fmt.Printf("  Network: %s\n", st.NetworkID)
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("daemon may still be starting; use 'veld status' to check\n")
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
		fmt.Printf("daemon not running\n")
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
			fmt.Printf("daemon stopped\n")
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("daemon shutdown timeout\n")
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
		fmt.Printf("daemon not running\n")
		return nil
	}

	st, err := getStatus(sock)
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	if st == nil {
		fmt.Printf("daemon not responding\n")
		return nil
	}

	fmt.Printf("Daemon Status:\n")
	fmt.Printf("  Running: %v\n", st.Running)
	if st.VPNAddr != "" {
		fmt.Printf("  VPN Address: %s\n", st.VPNAddr)
	}
	if st.PeerID != "" {
		fmt.Printf("  Peer ID: %s\n", st.PeerID)
	}
	if st.NetworkID != "" {
		fmt.Printf("  Network: %s\n", st.NetworkID)
	}
	if st.CoordAddr != "" {
		fmt.Printf("  Coordinator: %s\n", st.CoordAddr)
	}
	fmt.Printf("  Peers (%d):\n", len(st.Peers))
	for _, p := range st.Peers {
		fmt.Printf("    %s (%s)\n", p.VPNAddr, p.State)
		if p.Endpoint != "" {
			fmt.Printf("      Endpoint: %s\n", p.Endpoint)
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
	loginServer    string
	loginNetworkID string
	loginToken     string
	loginConfigPath string
)

func init() {
	loginCmd.Flags().StringVar(&loginServer, "server", "", "coordinator server address")
	loginCmd.Flags().StringVar(&loginNetworkID, "network-id", "", "network ID")
	loginCmd.Flags().StringVar(&loginToken, "token", "", "auth token")
	loginCmd.Flags().StringVar(&loginConfigPath, "config", "", "config file path")
}

func runLogin(cobraCmd *cobra.Command, args []string) error {
	cfgPath, err := getConfigPath(loginConfigPath)
	if err != nil {
		return err
	}

	if loginToken != "" && loginServer != "" {
		return saveCredentials(loginServer, loginNetworkID, loginToken, cfgPath)
	}

	return runBrowserAuthFlow(cfgPath)
}

func saveCredentials(server, networkID, token, cfgPath string) error {
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

	fmt.Printf("Logged in. Credentials saved to %s\n", cfgPath)
	return nil
}

func runBrowserAuthFlow(cfgPath string) error {
	fmt.Printf("Opening %s in your browser...\n", cliAuthPageURL)
	openBrowserURL(cliAuthPageURL)

	fmt.Printf("Enter auth code: ")
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

	return saveCredentials(server, networkID, token, cfgPath)
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
		body, _ := io.ReadAll(resp.Body)
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
	Short: "Join a network using a token",
	Args:  cobra.ExactArgs(1),
	RunE:  runJoin,
}

var (
	joinServer      string
	joinNetworkID   string
	joinConfigPath  string
)

func init() {
	joinCmd.Flags().StringVar(&joinServer, "server", "", "coordinator server address (default: infer from token)")
	joinCmd.Flags().StringVar(&joinNetworkID, "network-id", "", "network ID (default: infer from token)")
	joinCmd.Flags().StringVar(&joinConfigPath, "config", "", "config file path")
}

func runJoin(cobraCmd *cobra.Command, args []string) error {
	token := args[0]
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

	fmt.Printf("saved token to %s\n", cfgPath)
	fmt.Printf("use 'veld up' to connect\n")
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
				IfaceName:    "tun0",
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

func writeConfig(path string, cfg *config.Config) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

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
		io.ReadAll(resp.Body)
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
	io.ReadAll(resp.Body)
	resp.Body.Close()
	return nil
}
