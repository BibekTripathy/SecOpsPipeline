package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/BibekTripathy/SecOpsPipeline/internal/finding"
)

// DefaultOSVEndpoint is the public OSV API.
const DefaultOSVEndpoint = "https://api.osv.dev"

// OSVClient queries the OSV database.
//
// It makes two kinds of call: one batched query that asks which packages
// are affected at all, then one detail fetch per distinct vulnerability.
// The batch keeps the per-push cost to a single round trip in the common
// case, and the detail fetches are cached, because an advisory's contents
// change far more slowly than a push arrives.
type OSVClient struct {
	Endpoint string
	HTTP     *http.Client
	Cache    Cache
}

// NewOSVClient returns a client with a sensible timeout.
//
// The timeout is deliberately short. This call sits in the push path, and
// a developer waiting on an unreachable vulnerability database is worse
// than a scan that fails and lets the policy's fail_closed setting decide.
func NewOSVClient(cache Cache) *OSVClient {
	return &OSVClient{
		Endpoint: DefaultOSVEndpoint,
		HTTP:     &http.Client{Timeout: 15 * time.Second},
		Cache:    cache,
	}
}

// Cache stores vulnerability records between pushes.
type Cache interface {
	Get(id string) (Vulnerability, bool)
	Put(id string, v Vulnerability)
}

// osv API payloads, only the fields that are used.

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package osvPackage `json:"package"`
		Ranges  []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// Query implements Client.
func (c *OSVClient) Query(ctx context.Context, pkgs []Package) (map[Package][]Vulnerability, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}

	req := osvBatchRequest{Queries: make([]osvQuery, len(pkgs))}
	for i, p := range pkgs {
		req.Queries[i] = osvQuery{
			Package: osvPackage{Name: p.Name, Ecosystem: p.Ecosystem},
			Version: p.Version,
		}
	}

	var batch osvBatchResponse
	if err := c.post(ctx, "/v1/querybatch", req, &batch); err != nil {
		return nil, err
	}
	// The API contract is one result per query, in order. A mismatch means
	// results would be attributed to the wrong package, so fail rather
	// than guess.
	if len(batch.Results) != len(pkgs) {
		return nil, fmt.Errorf("osv returned %d results for %d queries", len(batch.Results), len(pkgs))
	}

	out := map[Package][]Vulnerability{}
	for i, res := range batch.Results {
		for _, v := range res.Vulns {
			vuln, err := c.vulnerability(ctx, v.ID)
			if err != nil {
				return nil, err
			}
			vuln.FixedIn = fixedVersion(vuln, pkgs[i])
			out[pkgs[i]] = append(out[pkgs[i]], vuln)
		}
	}
	return out, nil
}

// vulnerability fetches one advisory, through the cache.
func (c *OSVClient) vulnerability(ctx context.Context, id string) (Vulnerability, error) {
	if c.Cache != nil {
		if v, ok := c.Cache.Get(id); ok {
			return v, nil
		}
	}

	var raw osvVuln
	if err := c.get(ctx, "/v1/vulns/"+id, &raw); err != nil {
		return Vulnerability{}, err
	}

	v := Vulnerability{
		ID:       raw.ID,
		Summary:  summaryOf(raw),
		Severity: severityOf(raw),
		Aliases:  raw.Aliases,
		fixed:    fixedVersions(raw),
	}
	if c.Cache != nil {
		c.Cache.Put(id, v)
	}
	return v, nil
}

func summaryOf(raw osvVuln) string {
	if raw.Summary != "" {
		return raw.Summary
	}
	// Some records carry only a long details body; the first line of it
	// is a reasonable stand-in for a one-line summary.
	if i := strings.IndexByte(raw.Details, '\n'); i > 0 {
		return raw.Details[:i]
	}
	return raw.Details
}

// severityOf maps an OSV record onto our severity scale.
//
// The curator's own rating wins where there is one, because it reflects
// context a vector does not carry. Otherwise the CVSS v3 base score is
// computed from the vector. Only a record with neither falls back, and
// Medium is chosen there so an unrated advisory is neither silently
// ignored nor able to block a push on its own.
func severityOf(raw osvVuln) finding.Severity {
	switch strings.ToUpper(raw.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MODERATE", "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	}

	for _, sev := range raw.Severity {
		if !strings.HasPrefix(strings.ToUpper(sev.Type), "CVSS_V3") {
			continue
		}
		if score, ok := CVSSScore(sev.Score); ok {
			return SeverityFromScore(score)
		}
	}
	return finding.SeverityMedium
}

// fixedVersions collects the fixed version per affected package name.
func fixedVersions(raw osvVuln) map[string]string {
	out := map[string]string{}
	for _, a := range raw.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					out[a.Package.Name] = e.Fixed
				}
			}
		}
	}
	return out
}

func fixedVersion(v Vulnerability, p Package) string { return v.fixed[p.Name] }

func (c *OSVClient) post(ctx context.Context, path string, body, into any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode osv request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint()+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, into)
}

func (c *OSVClient) get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint()+path, nil)
	if err != nil {
		return fmt.Errorf("build osv request: %w", err)
	}
	return c.do(req, into)
}

func (c *OSVClient) do(req *http.Request, into any) error {
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("osv %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Cap the body: an error page should not become a log flood.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("osv %s: %s: %s", req.URL.Path, resp.Status, strings.TrimSpace(string(snippet)))
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("decode osv response from %s: %w", req.URL.Path, err)
	}
	return nil
}

func (c *OSVClient) endpoint() string {
	if c.Endpoint == "" {
		return DefaultOSVEndpoint
	}
	return strings.TrimSuffix(c.Endpoint, "/")
}

// MemoryCache is a process-lifetime vulnerability cache.
//
// Advisory contents change slowly, so caching for the life of the gateway
// is safe and removes almost all detail fetches after warm-up. An on-disk
// cache that survives restarts is the natural next step.
type MemoryCache struct {
	mu sync.RWMutex
	m  map[string]Vulnerability
}

func NewMemoryCache() *MemoryCache { return &MemoryCache{m: map[string]Vulnerability{}} }

func (c *MemoryCache) Get(id string) (Vulnerability, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.m[id]
	return v, ok
}

func (c *MemoryCache) Put(id string, v Vulnerability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = v
}
