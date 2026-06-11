// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//
// veld-tray — system tray status indicator for the Veld VPN daemon.
//
// Platforms:
//   Linux   requires libayatana-appindicator3 or libgtk-3 (CGO)
//   macOS   native AppKit via CGO
//   Windows native Win32 via CGO
//
// Build:
//   go build -o veld-tray .
//
// The binary communicates with veld-daemon over its local Unix socket IPC.
// No coord server connection is required.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/getlantern/systray"
)

const (
	dashboardURL = "https://app.veldmesh.io"
	pollInterval = 3 * time.Second
	appVersion   = "dev"
)

func main() {
	systray.Run(onReady, onExit)
}

func onReady() {
	sockPath := defaultSocketPath()
	client := newIPCClient(sockPath)

	systray.SetIcon(iconDisconnected)
	systray.SetTooltip("Veld VPN")

	// Status line (disabled — display only)
	mStatus := systray.AddMenuItem("Not connected", "Current VPN status")
	mStatus.Disable()

	systray.AddSeparator()

	mToggle := systray.AddMenuItem("Connect", "Start or stop the VPN")
	mDashboard := systray.AddMenuItem("Open Dashboard", "Open the web dashboard")

	systray.AddSeparator()

	mAbout := systray.AddMenuItem(fmt.Sprintf("Veld %s", appVersion), "About this application")
	mAbout.Disable()

	mQuit := systray.AddMenuItem("Quit", "Exit the tray application")

	// connected is updated by the polling goroutine and read by the event loop.
	var connected atomic.Bool

	// Polling goroutine: queries the daemon and updates menu items.
	go func() {
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		// Run an immediate poll before the first tick.
		update := func() {
			st := queryStatus(client)
			nowConnected := st != nil && st.Running
			prev := connected.Swap(nowConnected)

			if nowConnected == prev {
				// State unchanged — just refresh the address label.
				if nowConnected && st != nil {
					label := st.VPNAddr
					if label == "" {
						label = "connected"
					}
					mStatus.SetTitle(label)
				}
				return
			}

			if nowConnected {
				systray.SetIcon(iconConnected)
				label := st.VPNAddr
				if label == "" {
					label = "connected"
				}
				mStatus.SetTitle(label)
				mToggle.SetTitle("Disconnect")
			} else {
				systray.SetIcon(iconDisconnected)
				mStatus.SetTitle("Not connected")
				mToggle.SetTitle("Connect")
			}
		}

		update()
		for range ticker.C {
			update()
		}
	}()

	// Event loop
	for {
		select {
		case <-mToggle.ClickedCh:
			if connected.Load() {
				sendShutdown(client)
			} else {
				startDaemon()
			}

		case <-mDashboard.ClickedCh:
			openBrowser(dashboardURL)

		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func onExit() {}

// startDaemon launches veld-daemon as a detached background process.
func startDaemon() {
	daemonBin := "veld-daemon"
	if self, err := os.Executable(); err == nil {
		// Prefer a sibling binary in the same directory.
		candidate := siblingPath(self, daemonBin)
		if _, err := os.Stat(candidate); err == nil {
			daemonBin = candidate
		}
	}
	cmd := exec.Command(daemonBin)
	cmd.Start() //nolint:errcheck
}

// openBrowser opens url in the default system browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux, bsd
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start() //nolint:errcheck
}

// siblingPath returns the path of name in the same directory as self.
func siblingPath(self, name string) string {
	return filepath.Join(filepath.Dir(self), name)
}
