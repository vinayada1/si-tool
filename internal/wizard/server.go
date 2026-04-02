// Package wizard provides a web-based UI for generating security-insights.yml
package wizard

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/vinayada1/si-tool/internal/generator"
	"github.com/vinayada1/si-tool/internal/scanner"
	"github.com/vinayada1/si-tool/internal/validator"
	"github.com/vinayada1/si-tool/pkg/model"
)

// Server serves the wizard web UI
type Server struct {
	token      string
	repoURL    string
	outputPath string
	verbose    bool
	port       int
}

// NewServer creates a new wizard server
func NewServer(token, repoURL, outputPath string, verbose bool, port int) *Server {
	return &Server{
		token:      token,
		repoURL:    repoURL,
		outputPath: outputPath,
		verbose:    verbose,
		port:       port,
	}
}

// Start starts the wizard web server and opens a browser
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/preview", s.handlePreview)
	mux.HandleFunc("/api/generate", s.handleGenerate)
	mux.HandleFunc("/api/validate", s.handleValidate)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	url := fmt.Sprintf("http://%s", listener.Addr().String())
	fmt.Printf("🧙 Wizard running at %s\n", url)
	fmt.Println("Press Ctrl+C to stop")

	// Open browser after a brief delay
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(url)
	}()

	server := &http.Server{Handler: mux}
	return server.Serve(listener)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	}
	if cmd != nil {
		_ = cmd.Start()
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Inject the initial repo URL so the page auto-scans on load
	page := strings.Replace(indexHTML, "{{REPO_URL}}", html.EscapeString(s.repoURL), 1)
	page = strings.Replace(page, "{{OUTPUT_PATH}}", html.EscapeString(s.outputPath), 1)
	fmt.Fprint(w, page)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RepoURL string `json:"repoUrl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	targetURL := req.RepoURL
	if targetURL == "" {
		targetURL = s.repoURL
	}
	if targetURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Repository URL is required"})
		return
	}

	ctx := context.Background()
	githubScanner, err := scanner.NewGitHubScanner(s.token, targetURL, s.verbose)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Failed to initialize scanner: %v", err)})
		return
	}

	githubData, err := githubScanner.Scan(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Failed to scan repository: %v", err)})
		return
	}

	builder := generator.NewBuilder(s.verbose)
	insights := builder.BuildInsights(githubData)

	writeJSON(w, http.StatusOK, insights)
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var insights model.SecurityInsights
	if err := json.NewDecoder(r.Body).Decode(&insights); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Invalid data: %v", err)})
		return
	}

	writer := generator.NewWriter(false)
	yamlBytes, err := writer.ToYAML(insights)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Failed to generate YAML: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(yamlBytes)})
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		model.SecurityInsights
		OutputPath string `json:"outputPath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Invalid data: %v", err)})
		return
	}

	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = s.outputPath
	}

	writer := generator.NewWriter(s.verbose)
	opts := generator.WriteOptions{
		Force: true,
	}

	if err := writer.Write(req.SecurityInsights, outputPath, opts); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Failed to write file: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("Written to %s", outputPath),
		"path":    outputPath,
	})
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	v := validator.NewCUEValidator("", false)
	result, err := v.Validate([]byte(req.YAML))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Validation error: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
