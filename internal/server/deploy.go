package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func deploySecret() string { return os.Getenv("DEPLOY_SECRET") }

func deployWorkspaceRoot() string {
	if v := os.Getenv("WORKSPACE_ROOT"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Workspace")
}

func deployTmuxSession() string {
	if v := os.Getenv("TMUX_SESSION"); v != "" {
		return v
	}
	return "servers"
}

func deployServiceName() string {
	if v := os.Getenv("SERVICE_NAME"); v != "" {
		return v
	}
	return "bitwrap"
}

func deployProjectDirName() string {
	if v := os.Getenv("PROJECT_DIR"); v != "" {
		return v
	}
	return "bitwrap-io"
}

// HandleDeployWebhook etc. are exported so the existing routing switch in
// server.go can dispatch to them; bitwrap-io routes via a giant switch
// rather than a mux.
func (s *Server) HandleDeployWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	secret := deploySecret()
	if secret == "" {
		http.Error(w, "deploy not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if !verifyDeployHMAC(secret, body, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "invalid signature", http.StatusForbidden)
		return
	}
	var payload struct {
		Ref string `json:"ref"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if payload.Ref != "refs/heads/main" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ignored: %s", payload.Ref)
		return
	}
	go func() {
		log.Printf("[deploy] webhook triggered for %s", payload.Ref)
		output, err := runDeploySync()
		if err != nil {
			log.Printf("[deploy] failed: %v\n%s", err, output)
			return
		}
		log.Printf("[deploy] success, scheduling restart")
		scheduleDeployRestart()
	}()
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, "deploy started")
}

func (s *Server) HandleAdminDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkDeployAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Minute))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	write := func(msg string) { fmt.Fprint(w, msg); flusher.Flush() }

	write("Starting deploy...\n\n")
	output, err := runDeploySync()
	write(output)
	if err != nil {
		write(fmt.Sprintf("\nDEPLOY FAILED: %v\n", err))
		return
	}
	write("\nDeploy succeeded. Scheduling restart in 2s...\n")
	flusher.Flush()
	go scheduleDeployRestart()
}

func (s *Server) HandleAdminLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkDeployAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	lines := 100
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			lines = n
		}
	}
	target := fmt.Sprintf("%s:%s", deployTmuxSession(), deployServiceName())
	cmd := exec.Command("tmux", "capture-pane", "-t", target, "-p", "-S", fmt.Sprintf("-%d", lines))
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("tmux error: %v\n%s", err, out), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(out)
}

func verifyDeployHMAC(secret string, body []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sig, err := hex.DecodeString(signature[7:])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
}

func checkDeployAuth(r *http.Request) bool {
	secret := deploySecret()
	if secret == "" {
		return false
	}
	if r.Header.Get("X-Deploy-Token") == secret {
		return true
	}
	if r.URL.Query().Get("token") == secret {
		return true
	}
	return false
}

func runDeploySync() (string, error) {
	var buf strings.Builder
	projectDir := filepath.Join(deployWorkspaceRoot(), deployProjectDirName())

	run := func(desc string, args ...string) error {
		buf.WriteString(fmt.Sprintf("==> %s\n    cd %s && %s\n", desc, projectDir, strings.Join(args, " ")))
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = projectDir
		out, err := cmd.CombinedOutput()
		buf.Write(out)
		buf.WriteString("\n")
		if err != nil {
			return fmt.Errorf("%s: %w", desc, err)
		}
		return nil
	}
	if err := run("git fetch", "git", "fetch", "origin", "main"); err != nil {
		return buf.String(), err
	}
	if err := run("verify signature", "git", "verify-commit", "origin/main"); err != nil {
		return buf.String(), fmt.Errorf("refusing to deploy unsigned/untrusted HEAD: %w", err)
	}
	if err := run("fast-forward", "git", "merge", "--ff-only", "origin/main"); err != nil {
		return buf.String(), err
	}
	if err := run("make build", "make", "build"); err != nil {
		return buf.String(), err
	}
	buf.WriteString("==> Build complete\n")
	return buf.String(), nil
}

func scheduleDeployRestart() {
	time.Sleep(2 * time.Second)
	home, _ := os.UserHomeDir()
	servicesScript := filepath.Join(home, "services")
	log.Printf("[deploy] restarting %s via %s", deployServiceName(), servicesScript)
	cmd := exec.Command("nohup", servicesScript, "restart", deployServiceName())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("[deploy] restart failed: %v", err)
		return
	}
	_ = cmd.Process.Release()
	log.Printf("[deploy] exiting for restart")
	os.Exit(0)
}
