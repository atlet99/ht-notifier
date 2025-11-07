// slack_api_extractor.go
package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	slackAPIHost  = "api.slack.com"
	slackDocsHost = "docs.slack.dev"
	pathParamID   = "{id}"

	defaultMaxPages    = 1200
	defaultMaxDepth    = 8
	defaultHTTPTimeout = 25 * time.Second
	defaultReadLimit   = 4096
	minMatchLength     = 2
	minSCIMEndpoints   = 4
	minMatchLengthLong = 3
)

/*
Slack API extractor (v1.8.2)

Adds:
- Seeds for docs reference indexes:
    • https://docs.slack.dev/reference/methods/
    • https://docs.slack.dev/reference/web-api/methods/
- Wide scan on docs.slack.dev for /reference(?:/web-api)?/methods/<method>
  across HTML and embedded Next.js JSON.
Keeps:
- Sitemap crawl + /methods root + /methods/<family> pages on api.slack.com
- Next.js hydration parsing (__NEXT_DATA__)
- SCIM normalization & dedupe
*/

var (
	flagStart   = flag.String("start", "https://docs.slack.dev/apis/", "Seed URL (docs.slack.dev or api.slack.com)")
	flagMax     = flag.Int("maxPages", defaultMaxPages, "Max pages to fetch")
	flagDepth   = flag.Int("maxDepth", defaultMaxDepth, "Max crawl depth")
	flagQuiet   = flag.Bool("q", false, "Quiet mode")
	flagTimeout = flag.Duration("timeout", defaultHTTPTimeout, "HTTP timeout")
)

var allowedHosts = map[string]bool{
	"docs.slack.dev": true,
	"api.slack.com":  true,
}

type qitem struct {
	URL   *url.URL
	Depth int
}

func newClient() *http.Client { return &http.Client{Timeout: *flagTimeout} }

func fetch(client *http.Client, raw string) (string, error) {
	req, err := http.NewRequest("GET", raw, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "slack-api-extractor/1.8.2")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, defaultReadLimit))
		return "", fmt.Errorf("HTTP %d for %s: %s", resp.StatusCode, raw, strings.TrimSpace(string(b)))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ===== Regex =====
var (
	reHref           = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	reAPIMethodPath  = regexp.MustCompile(`^/methods/([a-z0-9][a-z0-9._\-]*)/?$`)
	reDocsMethodPath = regexp.MustCompile(`^/reference(?:/web-api)?/methods/([a-z0-9][a-z0-9._\-]*)/?$`)

	// wide scan: /methods/<family.method>
	reAnyMethodPathAPI = regexp.MustCompile(`(?i)/methods/([a-z0-9][a-z0-9._\-]*\.[a-z0-9._\-]+)/*(?:\?[^"'\s<>}]*)?`)
	// wide scan: /reference.../methods/<method>
	reAnyMethodPathDocs = regexp.MustCompile(
		`(?i)/reference(?:/web-api)?/methods/([a-z0-9][a-z0-9._\-]+)/*(?:\?[^"'\s<>}]*)?`)

	// Next.js hydration JSON
	reNextDataScript = regexp.MustCompile(`(?is)<script[^>]+id=["']__NEXT_DATA__["'][^>]*>\s*(\{.*?\})\s*</script>`)

	// SCIM
	reSCIMLine = regexp.MustCompile(
		`(?i)\b(GET|POST|PUT|PATCH|DELETE)\s+(/(?:ServiceProviderConfigs|Schemas(?:/Users|/Groups)?|` +
			`ResourceTypes|Users(?:/[<>\w\-\{\}]+)?|Groups(?:/[<>\w\-\{\}]+)?))`)
	reSCIMKey = regexp.MustCompile(
		`(?m)^\s*/(ServiceProviderConfigs|Schemas(?:/Users|/Groups)?|ResourceTypes|` +
			`Users(?:/[<>\w\-\{\}]+)?|Groups(?:/[<>\w\-\{\}]+)?)\s*:`)
	reSCIMAny = regexp.MustCompile(
		`(?i)(/ServiceProviderConfigs|/Schemas(?:/Users|/Groups)?|/ResourceTypes|` +
			`/Users(?:/[<>\w\-\{\}]+)?|/Groups(?:/[<>\w\-\{\}]+)?)`)

	reStaticExt = regexp.MustCompile(`(?i)\.(css|js|mjs|png|jpg|jpeg|svg|gif|ico|webp|woff2?|ttf|map|pdf|rss|atom|xml)$`)
	reAbsWebAPI = regexp.MustCompile(`https://slack\.com/api/([a-z0-9][a-z0-9._\-]*)`)
	reLocTag    = regexp.MustCompile(`(?is)<loc>\s*([^<\s]+)\s*</loc>`)
)

// ===== Sitemap structs =====
type sitemapIndex struct {
	Sitemaps []sitemapChild `xml:"sitemap"`
}
type sitemapChild struct {
	Loc string `xml:"loc"`
}
type urlset struct {
	URLs []urlEntry `xml:"url"`
}
type urlEntry struct {
	Loc string `xml:"loc"`
}

// seeds
var webFamilies = []string{
	"admin", "admin.analytics", "admin.apps", "admin.auth", "admin.conversations", "admin.emoji",
	"admin.functions", "admin.invite_requests", "admin.teams", "admin.usergroups", "admin.users",
	"api",
	"apps", "apps.connections", "apps.event.authorizations", "apps.permissions", "apps.uninstall",
	"assistant", "auth",
	"bookmarks", "bots",
	"calls", "canvases",
	"chat",
	"conversations",
	"dialog", "dnd",
	"emoji",
	"files", "files.remote",
	"functions",
	"migration",
	"oauth", "openid",
	"pins",
	"reactions",
	"reminders", "rtm",
	"search", "stars",
	"team", "tooling",
	"usergroups", "users",
	"views",
	"workflows", "workflows.steps",
}

func main() {
	flag.Parse()

	startURL, err := parseStartURL()
	if err != nil {
		fmt.Println(err)
		return
	}

	client := newClient()
	queue := initializeQueue(startURL)
	seen := map[string]bool{}
	webMethods := map[string]struct{}{}
	scimURLs := map[string]struct{}{}

	crawlPages(client, &queue, seen, webMethods, scimURLs)
	printResults(webMethods, scimURLs)
}

// parseStartURL parses and validates the start URL
func parseStartURL() (*url.URL, error) {
	start := *flagStart
	if flag.NArg() > 0 && (start == "" || start == "https://docs.slack.dev/apis/") {
		start = flag.Arg(0)
	}
	u, err := url.Parse(start)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("provide a valid absolute URL for -start (e.g., https://docs.slack.dev/apis/)")
	}
	if !allowedHosts[u.Host] {
		return nil, fmt.Errorf("start URL host must be docs.slack.dev or api.slack.com")
	}
	return u, nil
}

// initializeQueue initializes the crawl queue with seed URLs
func initializeQueue(startURL *url.URL) []qitem {
	queue := []qitem{{URL: startURL, Depth: 0}}
	queue = appendSeedURLs(queue)
	return queue
}

// appendSeedURLs appends seed URLs to the queue
func appendSeedURLs(queue []qitem) []qitem {
	seeds := []string{
		"https://api.slack.com/sitemap.xml",
		"https://api.slack.com/methods",
		"https://docs.slack.dev/reference/methods/",
		"https://docs.slack.dev/reference/web-api/methods/",
		"https://docs.slack.dev/reference/scim-api/",
	}
	for _, seed := range seeds {
		if nu, _ := url.Parse(seed); nu != nil {
			queue = append(queue, qitem{URL: nu, Depth: 0})
		}
	}
	for _, fam := range webFamilies {
		if nu, _ := url.Parse("https://api.slack.com/methods/" + fam); nu != nil {
			queue = append(queue, qitem{URL: nu, Depth: 0})
		}
	}
	return queue
}

// crawlPages performs the main crawling loop
func crawlPages(
	client *http.Client,
	queue *[]qitem,
	seen map[string]bool,
	webMethods map[string]struct{},
	scimURLs map[string]struct{},
) {
	fetched := 0
	for len(*queue) > 0 && fetched < *flagMax {
		item := (*queue)[0]
		*queue = (*queue)[1:]

		if !shouldProcessItem(item, seen) {
			continue
		}
		seen[item.URL.String()] = true

		body, err := fetch(client, item.URL.String())
		if err != nil {
			if !*flagQuiet {
				fmt.Printf("Fetch error: %s: %v\n", item.URL, err)
			}
			continue
		}
		fetched++
		if !*flagQuiet {
			fmt.Printf("Fetched [%d/%d] %s\n", fetched, *flagMax, item.URL)
		}

		processFetchedPage(item, body, webMethods, scimURLs, queue, seen)
	}
}

// shouldProcessItem checks if an item should be processed
func shouldProcessItem(item qitem, seen map[string]bool) bool {
	if item.Depth > *flagDepth {
		return false
	}
	if seen[item.URL.String()] {
		return false
	}
	return true
}

// processFetchedPage processes a fetched page
func processFetchedPage(
	item qitem,
	body string,
	webMethods map[string]struct{},
	scimURLs map[string]struct{},
	queue *[]qitem,
	seen map[string]bool,
) {
	if item.URL.Host == slackAPIHost && strings.HasSuffix(item.URL.Path, ".xml") {
		extractFromSitemap(item.URL, body, webMethods, queue, item.Depth)
		return
	}

	extractFromPage(item.URL, body, webMethods, scimURLs)
	discoverLinks(item, body, queue, seen)
}

// discoverLinks discovers and adds new links from the page
func discoverLinks(item qitem, body string, queue *[]qitem, seen map[string]bool) {
	for _, m := range reHref.FindAllStringSubmatch(body, -1) {
		if len(m) < minMatchLength {
			continue
		}
		h := strings.TrimSpace(m[1])
		if !isValidLink(h) {
			continue
		}
		nu, err := item.URL.Parse(h)
		if err != nil {
			continue
		}
		if !isAllowedLink(nu) {
			continue
		}
		if !seen[nu.String()] {
			*queue = append(*queue, qitem{URL: nu, Depth: item.Depth + 1})
		}
	}
}

// isValidLink checks if a link is valid
func isValidLink(h string) bool {
	if h == "" || strings.HasPrefix(h, "mailto:") || strings.HasPrefix(h, "javascript:") {
		return false
	}
	return true
}

// isAllowedLink checks if a link is allowed
func isAllowedLink(nu *url.URL) bool {
	if !allowedHosts[nu.Host] {
		return false
	}
	switch nu.Host {
	case slackDocsHost:
		if !strings.HasPrefix(nu.Path, "/apis/") && !strings.HasPrefix(nu.Path, "/reference/") {
			return false
		}
	case slackAPIHost:
		if !strings.HasPrefix(nu.Path, "/methods") {
			return false
		}
	}
	return !reStaticExt.MatchString(strings.ToLower(nu.Path))
}

// printResults prints the final results
func printResults(webMethods, scimURLs map[string]struct{}) {
	webEndpoints := buildWebEndpoints(webMethods)
	scimEndpoints := buildSCIMEndpoints(scimURLs)

	fmt.Println("== Slack Web API endpoints ==")
	for _, e := range webEndpoints {
		fmt.Println(e)
	}
	fmt.Printf("\nTotal Web API endpoints: %d\n\n", len(webEndpoints))

	fmt.Println("== Slack SCIM API endpoints ==")
	for _, e := range scimEndpoints {
		fmt.Println(e)
	}
	fmt.Printf("\nTotal SCIM API endpoints: %d\n", len(scimEndpoints))
}

// buildWebEndpoints builds the list of web API endpoints
func buildWebEndpoints(webMethods map[string]struct{}) []string {
	webEndpoints := make([]string, 0, len(webMethods))
	for m := range webMethods {
		webEndpoints = append(webEndpoints, "https://slack.com/api/"+m)
	}
	sort.Strings(webEndpoints)
	return webEndpoints
}

// buildSCIMEndpoints builds the list of SCIM API endpoints
func buildSCIMEndpoints(scimURLs map[string]struct{}) []string {
	scimEndpoints := make([]string, 0, len(scimURLs))
	for p := range scimURLs {
		scimEndpoints = append(scimEndpoints, trimTrailingSlash(p))
	}
	if len(scimEndpoints) < minSCIMEndpoints {
		addDefaultSCIMEndpoints(scimURLs)
		scimEndpoints = scimEndpoints[:0]
		for p := range scimURLs {
			scimEndpoints = append(scimEndpoints, trimTrailingSlash(p))
		}
	}
	scimEndpoints = uniqueStrings(scimEndpoints)
	sort.Strings(scimEndpoints)
	return scimEndpoints
}

// addDefaultSCIMEndpoints adds default SCIM endpoints if not enough were found
func addDefaultSCIMEndpoints(scimURLs map[string]struct{}) {
	scimPaths := []string{
		"/Users", "/Users/" + pathParamID, "/Groups", "/Groups/" + pathParamID,
		"/Schemas", "/ServiceProviderConfigs", "/ResourceTypes",
	}
	for _, rel := range scimPaths {
		scimURLs["https://api.slack.com/scim/v1"+rel] = struct{}{}
		scimURLs["https://api.slack.com/scim/v2"+rel] = struct{}{}
	}
}

// ===== Sitemap extraction =====
func extractFromSitemap(
	base *url.URL,
	xmlStr string,
	webMethods map[string]struct{},
	queue *[]qitem,
	currentDepth int,
) {
	if extractSitemapIndex(base, xmlStr, queue, currentDepth) {
		return
	}
	if extractURLSet(base, xmlStr, webMethods) {
		return
	}
	extractLocTags(base, xmlStr, webMethods)
}

// extractSitemapIndex extracts sitemap index entries
func extractSitemapIndex(base *url.URL, xmlStr string, queue *[]qitem, currentDepth int) bool {
	var idx sitemapIndex
	if err := xml.Unmarshal([]byte(xmlStr), &idx); err != nil || len(idx.Sitemaps) == 0 {
		return false
	}
	for _, sm := range idx.Sitemaps {
		loc := strings.TrimSpace(sm.Loc)
		if loc == "" {
			continue
		}
		nu, err := base.Parse(loc)
		if err != nil {
			continue
		}
		if nu.Host == slackAPIHost {
			*queue = append(*queue, qitem{URL: nu, Depth: currentDepth + 1})
		}
	}
	return true
}

// extractURLSet extracts URL set entries
func extractURLSet(base *url.URL, xmlStr string, webMethods map[string]struct{}) bool {
	var set urlset
	if err := xml.Unmarshal([]byte(xmlStr), &set); err != nil || len(set.URLs) == 0 {
		return false
	}
	for _, e := range set.URLs {
		processURLSetEntry(base, e.Loc, webMethods)
	}
	return true
}

// processURLSetEntry processes a single URL set entry
func processURLSetEntry(base *url.URL, loc string, webMethods map[string]struct{}) {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return
	}
	nu, err := base.Parse(loc)
	if err != nil {
		return
	}
	if nu.Host != slackAPIHost {
		return
	}
	if mm := reAPIMethodPath.FindStringSubmatch(nu.Path); len(mm) == 2 && looksLikeMethod(mm[1]) {
		webMethods[mm[1]] = struct{}{}
	}
}

// extractLocTags extracts loc tags as fallback
func extractLocTags(base *url.URL, xmlStr string, webMethods map[string]struct{}) {
	for _, m := range reLocTag.FindAllStringSubmatch(xmlStr, -1) {
		if len(m) < minMatchLength {
			continue
		}
		nu, err := base.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		if nu.Host != "api.slack.com" {
			continue
		}
		if mm := reAPIMethodPath.FindStringSubmatch(nu.Path); len(mm) == 2 && looksLikeMethod(mm[1]) {
			webMethods[mm[1]] = struct{}{}
		}
	}
}

// ===== Page extraction =====
func extractFromPage(u *url.URL, html string, webMethods, scimURLs map[string]struct{}) {
	extractNextJSData(html, webMethods, scimURLs)
	extractAbsWebAPI(html, webMethods)
	extractFromAPIHost(u, html, webMethods)
	extractFromDocsHost(u, html, webMethods, scimURLs)
}

// extractNextJSData extracts data from Next.js embedded JSON
func extractNextJSData(html string, webMethods, scimURLs map[string]struct{}) {
	for _, m := range reNextDataScript.FindAllStringSubmatch(html, -1) {
		if len(m) < minMatchLength {
			continue
		}
		jsonStr := strings.TrimSpace(m[1])
		var tmp any
		if json.Unmarshal([]byte(jsonStr), &tmp) == nil {
			extractMethodsFromJSON(jsonStr, webMethods)
			extractSCIMFromJSON(jsonStr, scimURLs)
		}
	}
}

// extractMethodsFromJSON extracts methods from JSON string
func extractMethodsFromJSON(jsonStr string, webMethods map[string]struct{}) {
	for _, mm := range reAnyMethodPathAPI.FindAllStringSubmatch(jsonStr, -1) {
		if len(mm) >= 2 && looksLikeMethod(mm[1]) {
			webMethods[mm[1]] = struct{}{}
		}
	}
	for _, mm := range reAnyMethodPathDocs.FindAllStringSubmatch(jsonStr, -1) {
		if len(mm) >= 2 && mm[1] != "" {
			webMethods[mm[1]] = struct{}{}
		}
	}
}

// extractSCIMFromJSON extracts SCIM URLs from JSON string
func extractSCIMFromJSON(jsonStr string, scimURLs map[string]struct{}) {
	for _, sm := range reSCIMAny.FindAllString(jsonStr, -1) {
		addSCIM(scimURLs, sm)
	}
}

// extractAbsWebAPI extracts absolute web API URLs
func extractAbsWebAPI(html string, webMethods map[string]struct{}) {
	for _, m := range reAbsWebAPI.FindAllStringSubmatch(html, -1) {
		if len(m) == 2 && looksLikeMethod(m[1]) {
			webMethods[m[1]] = struct{}{}
		}
	}
}

// extractFromAPIHost extracts methods from api.slack.com pages
func extractFromAPIHost(u *url.URL, html string, webMethods map[string]struct{}) {
	if u.Host != slackAPIHost {
		return
	}
	extractMethodsFromHrefs(u, html, webMethods)
	extractMethodsFromHTML(u, html, webMethods)
}

// extractMethodsFromHrefs extracts methods from href links
func extractMethodsFromHrefs(u *url.URL, html string, webMethods map[string]struct{}) {
	for _, m := range reHref.FindAllStringSubmatch(html, -1) {
		if len(m) < minMatchLength {
			continue
		}
		nu, err := u.Parse(m[1])
		if err != nil {
			continue
		}
		if nu.Host != u.Host {
			continue
		}
		if mm := reAPIMethodPath.FindStringSubmatch(nu.Path); len(mm) == 2 && looksLikeMethod(mm[1]) {
			webMethods[mm[1]] = struct{}{}
		}
	}
}

// extractMethodsFromHTML extracts methods from HTML content
func extractMethodsFromHTML(_ *url.URL, html string, webMethods map[string]struct{}) {
	for _, m := range reAnyMethodPathAPI.FindAllStringSubmatch(html, -1) {
		if len(m) >= 2 && looksLikeMethod(m[1]) {
			webMethods[m[1]] = struct{}{}
		}
	}
}

// extractFromDocsHost extracts methods and SCIM from docs.slack.dev pages
func extractFromDocsHost(
	u *url.URL,
	html string,
	webMethods map[string]struct{},
	scimURLs map[string]struct{},
) {
	if u.Host != slackDocsHost {
		return
	}
	extractDocsMethods(u, html, webMethods)
	extractDocsSCIM(u, html, scimURLs)
}

// extractDocsMethods extracts methods from docs.slack.dev pages
func extractDocsMethods(u *url.URL, html string, webMethods map[string]struct{}) {
	path := u.Path
	if strings.Contains(path, "/reference/") && strings.Contains(path, "/methods/") {
		if mm := reDocsMethodPath.FindStringSubmatch(path); len(mm) == 2 && mm[1] != "" {
			webMethods[mm[1]] = struct{}{}
		}
	}
	extractDocsMethodsFromHrefs(u, html, webMethods)
	extractDocsMethodsFromHTML(html, webMethods)
}

// extractDocsMethodsFromHrefs extracts methods from href links on docs pages
func extractDocsMethodsFromHrefs(u *url.URL, html string, webMethods map[string]struct{}) {
	for _, m := range reHref.FindAllStringSubmatch(html, -1) {
		if len(m) < minMatchLength {
			continue
		}
		nu, err := u.Parse(m[1])
		if err != nil {
			continue
		}
		if nu.Host != u.Host {
			continue
		}
		if mm := reDocsMethodPath.FindStringSubmatch(nu.Path); len(mm) == 2 && mm[1] != "" {
			webMethods[mm[1]] = struct{}{}
		}
	}
}

// extractDocsMethodsFromHTML extracts methods from HTML body on docs pages
func extractDocsMethodsFromHTML(html string, webMethods map[string]struct{}) {
	for _, mm := range reAnyMethodPathDocs.FindAllStringSubmatch(html, -1) {
		if len(mm) >= 2 && mm[1] != "" {
			webMethods[mm[1]] = struct{}{}
		}
	}
}

// extractDocsSCIM extracts SCIM URLs from docs.slack.dev pages
func extractDocsSCIM(u *url.URL, html string, scimURLs map[string]struct{}) {
	path := u.Path
	if !strings.HasPrefix(path, "/reference/scim-api/") && path != "/reference/scim-api/" {
		return
	}
	extractSCIMFromLines(html, scimURLs)
	extractSCIMFromKeys(html, scimURLs)
	extractSCIMFromAny(html, scimURLs)
}

// extractSCIMFromLines extracts SCIM from method lines
func extractSCIMFromLines(html string, scimURLs map[string]struct{}) {
	for _, m := range reSCIMLine.FindAllStringSubmatch(html, -1) {
		if len(m) >= minMatchLengthLong {
			addSCIM(scimURLs, m[2])
		}
	}
}

// extractSCIMFromKeys extracts SCIM from key patterns
func extractSCIMFromKeys(html string, scimURLs map[string]struct{}) {
	for _, k := range reSCIMKey.FindAllString(html, -1) {
		key := strings.TrimSpace(strings.TrimSuffix(k, ":"))
		if !strings.HasPrefix(key, "/") {
			key = "/" + key
		}
		addSCIM(scimURLs, key)
	}
}

// extractSCIMFromAny extracts SCIM from any pattern
func extractSCIMFromAny(html string, scimURLs map[string]struct{}) {
	for _, p := range reSCIMAny.FindAllString(html, -1) {
		addSCIM(scimURLs, p)
	}
}

func addSCIM(dst map[string]struct{}, rel string) {
	rel = sanitizeSCIMExamples(rel)
	if rel == "" || rel == "/"+pathParamID {
		return
	}
	dst["https://api.slack.com/scim/v1"+rel] = struct{}{}
	dst["https://api.slack.com/scim/v2"+rel] = struct{}{}
}

func looksLikeMethod(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, r := range parts[0] {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// ===== SCIM helpers =====
func normalizeSCIMRel(rel string) string {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return ""
	}
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	rel = strings.ReplaceAll(rel, "//", "/")
	rel = strings.TrimRight(rel, " :")
	return rel
}

func sanitizeSCIMExamples(rel string) string {
	rel = normalizeSCIMRel(rel)
	if rel == "" {
		return ""
	}
	rel = strings.TrimSuffix(rel, "<")

	parts := strings.Split(rel, "/")
	for i, seg := range parts {
		if i == 0 {
			continue
		}
		s := strings.TrimSpace(seg)
		if s == "" {
			continue
		}
		switch {
		case s == pathParamID || s == pathParamID+"<":
			parts[i] = pathParamID
		case strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">"):
			parts[i] = pathParamID
		case isDigits(s):
			parts[i] = pathParamID
		case startsWithAny(s, "U", "S", "G"):
			parts[i] = pathParamID
		}
	}
	out := strings.Join(parts, "/")
	out = strings.ReplaceAll(out, pathParamID+"/"+pathParamID, pathParamID)
	out = strings.TrimSuffix(out, "/")
	return out
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
func startsWithAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// ===== utils =====
func trimTrailingSlash(s string) string {
	if strings.HasSuffix(s, "/") {
		return strings.TrimRight(s, "/")
	}
	return s
}
func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
