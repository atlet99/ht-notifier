// github_api_extractor.go
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---- Data structures for GitHub Contents API ----

type githubContent struct {
	Type        string `json:"type"`         // "file" | "dir" | "symlink" | "submodule"
	Name        string `json:"name"`         // file/dir name
	Path        string `json:"path"`         // repo path
	SHA         string `json:"sha"`          // blob sha
	Size        int64  `json:"size"`         // size in bytes (0 for dirs)
	URL         string `json:"url"`          // API URL for this content
	HTMLURL     string `json:"html_url"`     // GitHub web URL
	GitURL      string `json:"git_url"`      // Git data API URL
	DownloadURL string `json:"download_url"` // Raw download URL (may be empty)
	// For single-file fetch via contents API:
	Content  string `json:"content"`  // base64-encoded content (may be truncated by API)
	Encoding string `json:"encoding"` // "base64"
}

// ---- Flags / configuration ----

var (
	flagRepoURL = flag.String("url", "", "GitHub repo URL, e.g. https://github.com/mattermost/mattermost/tree/master/api/v4/source")
	flagQuiet   = flag.Bool("q", false, "Quiet mode (suppress per-file logs)")
	flagBranch  = flag.String("branch", "", "Override branch/ref (optional; auto-detected from URL otherwise)")
)

const ghAPIBase = "https://api.github.com"

// ---- Regex helpers ----
//
// We support three ways to discover API paths in text files:
// 1) Any literal appearance of `/api/...`
// 2) YAML keys like `url: /users/{id}` or `path: /users` → prefix with base when needed
// 3) OpenAPI `paths:` map keys like `/users/{id}:` → prefix with base when needed

var (
	// Any raw /api/... occurrence
	reAnyAPI = regexp.MustCompile(`/api/[A-Za-z0-9._~:/\-\{\}$begin:math:text$$end:math:text$$begin:math:display$$end:math:display$,]+`)

	// YAML scalar assignments like:
	//   url: /users/{id}
	//   path: "/teams/{team_id}/members"
	//   endpoint: '/channels'
	reYamlURL = regexp.MustCompile(`(?m)^\s*(?:-?\s*)?(?:url|path|endpoint)\s*:\s*['"]?(/[^'"\s]+)`)

	// OpenAPI "paths" keys, e.g.:
	// paths:
	//   /users/{user_id}:
	//   /channels/{channel_id}/posts:
	reOpenAPIPathKey = regexp.MustCompile(`(?m)^\s{0,6}/[^:\s]+:`)
)

// ---- Main ----

func main() {
	flag.Parse()

	repoURL := *flagRepoURL
	if repoURL == "" && flag.NArg() > 0 {
		repoURL = flag.Arg(0)
	}
	if repoURL == "" {
		fmt.Println("Usage:")
		fmt.Println("  go run github_api_extractor.go -url <github-repo-url>")
		fmt.Println("  go run github_api_extractor.go https://github.com/mattermost/mattermost/tree/master/api/v4/source")
		os.Exit(1)
	}

	owner, repo, ref, subpath, err := parseGitHubURL(repoURL, *flagBranch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid GitHub URL: %v\n", err)
		os.Exit(1)
	}

	// Heuristic base prefix:
	// - If the path contains "api/v4", default to "/api/v4"
	// - Otherwise fall back to "/api"
	basePrefix := "/api"
	lp := strings.ToLower("/" + subpath + "/")
	if strings.Contains(lp, "/api/v4/") {
		basePrefix = "/api/v4"
	}

	if !*flagQuiet {
		fmt.Printf("Owner: %s\nRepo: %s\nRef: %s\nPath: %s\n", owner, repo, ref, subpath)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	token := os.Getenv("GITHUB_TOKEN")

	found := map[string]struct{}{}

	// Walk through the repository subtree, collect paths from interesting files
	err = walkContents(client, token, owner, repo, ref, subpath, func(it githubContent) error {
		if it.Type == "file" && isAPISourceFile(it.Name) {
			if !*flagQuiet {
				fmt.Printf("→ scanning: %s\n", it.Path)
			}
			code, err := fetchFileContent(client, token, owner, repo, ref, it.Path)
			if err != nil {
				return fmt.Errorf("fetch file %s: %w", it.Path, err)
			}
			paths := extractAPIPathsFromText(code, basePrefix)
			for _, p := range paths {
				found[p] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print results
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)

	fmt.Println("Found API paths:")
	for _, p := range out {
		fmt.Println(p)
	}
	fmt.Printf("\nTotal API paths found: %d\n", len(out))
}

// ---- URL parsing & GitHub walking ----

// parseGitHubURL supports:
// - https://github.com/<owner>/<repo>
// - https://github.com/<owner>/<repo>/tree/<branch>/<path...>
// - https://github.com/<owner>/<repo>/blob/<branch>/<path...>
// If branch is missing, default to "master" (and later retry "main" at root on 404).
func parseGitHubURL(raw string, overrideRef string) (owner, repo, ref, subpath string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", "", err
	}
	if u.Host != "github.com" {
		return "", "", "", "", fmt.Errorf("host must be github.com")
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", "", "", fmt.Errorf("path must contain /<owner>/<repo>")
	}
	owner = parts[0]
	repo = parts[1]
	ref = "master"

	if len(parts) >= 3 {
		switch parts[2] {
		case "tree", "blob":
			if len(parts) >= 4 {
				ref = parts[3]
				if len(parts) >= 5 {
					subpath = strings.Join(parts[4:], "/")
				}
			}
		default:
			if len(parts) > 2 {
				subpath = strings.Join(parts[2:], "/")
			}
		}
	}

	if overrideRef != "" {
		ref = overrideRef
	}
	return owner, repo, ref, subpath, nil
}

// walkContents recursively traverses the repo subtree at a given ref.
func walkContents(client *http.Client, token, owner, repo, ref, p string, fn func(githubContent) error) error {
	apiURL := fmt.Sprintf("%s/repos/%s/%s/contents/%s", ghAPIBase, owner, repo, url.PathEscape(p))
	v := url.Values{}
	if ref != "" {
		v.Set("ref", ref)
	}
	full := apiURL
	if q := v.Encode(); q != "" {
		full += "?" + q
	}

	req, err := ghRequest("GET", full, token)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// If the root 404s on default branch, try swapping master/main once.
	if resp.StatusCode == http.StatusNotFound && p == "" && (ref == "master" || ref == "main") {
		alt := "main"
		if ref == "main" {
			alt = "master"
		}
		return walkContents(client, token, owner, repo, alt, p, fn)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("GET %s: %s: %s", full, resp.Status, strings.TrimSpace(string(body)))
	}

	// Decode either array (dir) or object (file). Try array first.
	var arr []githubContent
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&arr); err == nil {
		for _, it := range arr {
			if err := fn(it); err != nil {
				return err
			}
			switch it.Type {
			case "dir":
				if err := walkContents(client, token, owner, repo, ref, it.Path, fn); err != nil {
					return err
				}
			case "file":
				// handled by caller via fn(it)
			}
		}
		return nil
	}

	// Not an array → refetch as object
	req2, err := ghRequest("GET", full, token)
	if err != nil {
		return err
	}
	resp2, err := client.Do(req2)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()

	var obj githubContent
	if err := json.NewDecoder(resp2.Body).Decode(&obj); err != nil {
		return err
	}
	return fn(obj)
}

func ghRequest(method, rawURL, token string) (*http.Request, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "github-api-extractor/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

// ---- File fetching ----

// fetchFileContent fetches a file's content at a given ref.
// It prefers the Contents API (returns base64), then falls back to download URL or raw.githubusercontent.com.
func fetchFileContent(client *http.Client, token, owner, repo, ref, repoPath string) (string, error) {
	apiURL := fmt.Sprintf("%s/repos/%s/%s/contents/%s", ghAPIBase, owner, repo, url.PathEscape(repoPath))
	if ref != "" {
		apiURL += "?ref=" + url.QueryEscape(ref)
	}

	req, err := ghRequest("GET", apiURL, token)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Try direct raw content
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, ref, repoPath)
		return httpGetString(client, rawURL)
	}

	var c githubContent
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return "", err
	}

	// Decode embedded base64 content when available
	if c.Content != "" && strings.EqualFold(c.Encoding, "base64") {
		dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(c.Content, "\n", ""))
		if err != nil {
			return "", fmt.Errorf("base64 decode: %w", err)
		}
		return string(dec), nil
	}

	// Fallback to provided download URL
	if c.DownloadURL != "" {
		return httpGetString(client, c.DownloadURL)
	}

	// Last resort: raw.githubusercontent.com
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, ref, repoPath)
	return httpGetString(client, rawURL)
}

func httpGetString(client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "github-api-extractor/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return "", fmt.Errorf("GET %s: %s: %s", rawURL, resp.Status, strings.TrimSpace(string(b)))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- Extraction logic ----

// extractAPIPathsFromText scans arbitrary text (YAML/JSON/Go/etc.) and returns
// unique API paths. If a path does not start with "/api/", it will be prefixed
// with basePrefix (e.g., "/api/v4").
func extractAPIPathsFromText(text string, basePrefix string) []string {
	seen := map[string]struct{}{}
	add := func(p string) {
		p = normalizePath(p)
		if p == "" {
			return
		}
		if !strings.HasPrefix(p, "/api/") {
			// Prefix with provided base when not already /api/...
			p = normalizePath(basePrefix + p)
		}
		seen[p] = struct{}{}
	}

	// 1) Any raw /api/... occurrence
	for _, m := range reAnyAPI.FindAllString(text, -1) {
		add(m)
	}

	// 2) YAML url/path/endpoint scalars
	for _, m := range reYamlURL.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 {
			add(m[1])
		}
	}

	// 3) OpenAPI "paths" keys ("/users/{id}:" etc.)
	for _, line := range reOpenAPIPathKey.FindAllString(text, -1) {
		trimmed := strings.TrimSpace(line)
		// Remove trailing colon
		if strings.HasSuffix(trimmed, ":") {
			trimmed = strings.TrimSuffix(trimmed, ":")
		}
		// Expect it to start with "/"
		if strings.HasPrefix(trimmed, "/") {
			add(trimmed)
		}
	}

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// normalizePath collapses duplicate slashes (keeping the leading slash) and trims whitespace.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return p
	}
	parts := strings.Split(p, "/")
	clean := make([]string, 0, len(parts))
	for i, seg := range parts {
		if i == 0 {
			clean = append(clean, seg) // may be empty due to leading slash
			continue
		}
		if seg == "" {
			continue
		}
		clean = append(clean, seg)
	}
	res := strings.Join(clean, "/")
	if !strings.HasPrefix(res, "/") {
		res = "/" + res
	}
	return res
}

// isAPISourceFile selects files that may contain API paths.
func isAPISourceFile(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".yaml") ||
		strings.HasSuffix(n, ".yml") ||
		strings.HasSuffix(n, ".json") ||
		strings.HasSuffix(n, ".go")
}
