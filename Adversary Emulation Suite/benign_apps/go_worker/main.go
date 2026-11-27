package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

type status struct {
	Service string `json:"service"`
	State   string `json:"state"`
	Workers int    `json:"workers"`
}

func audit(file, line string) {
	dir := os.Getenv("BKAES_AUDIT_JOB_DIR")
	if dir == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, file), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintln(f, line)
}

func fail(reason string) {
	audit("bkaes-assertions.txt", "[BKAES_ASSERT_FAIL] go_worker "+reason)
	fmt.Fprintln(os.Stderr, reason)
	os.Exit(1)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status{"normal-go-worker", "healthy", runtime.NumCPU()})
	})
	mux.HandleFunc("/api/rates", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"base":"AUD","rates":{"USD":0.65,"EUR":0.59}}`)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen failed: " + err.Error())
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()

	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/api/status")
	if err != nil {
		fail("loopback request failed: " + err.Error())
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		fail("loopback response invalid")
	}
	var decoded status
	if json.Unmarshal(body, &decoded) != nil || decoded.State != "healthy" {
		fail("JSON decode failed")
	}

	values := []int{42, 7, 91, 13, 55, 21}
	sort.Ints(values)
	statePath := filepath.Join(os.TempDir(), fmt.Sprintf("bkaes-go-%d.json", os.Getpid()))
	encoded, _ := json.Marshal(map[string]any{"values": values, "status": decoded})
	if err := os.WriteFile(statePath, encoded, 0600); err != nil {
		fail("state write failed")
	}
	roundtrip, err := os.ReadFile(statePath)
	_ = os.Remove(statePath)
	if err != nil || len(roundtrip) != len(encoded) {
		fail("state roundtrip failed")
	}

	external := "disabled"
	if url := os.Getenv("BKAES_EXTERNAL_URL"); url != "" {
		r, requestErr := client.Get(url)
		if requestErr != nil {
			fail("optional external request failed")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
		r.Body.Close()
		external = fmt.Sprintf("status-%d", r.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = server.Shutdown(ctx)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		fail("server shutdown timed out")
	}
	outcome := fmt.Sprintf("[BKAES_OUTCOME] benign_go_worker=passed loopback=ok jsonBytes=%d external=%s", len(body), external)
	audit("bkaes-protection-outcome.txt", outcome)
	fmt.Println(outcome)
}
