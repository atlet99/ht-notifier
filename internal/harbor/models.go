package harbor

import (
	"fmt"
	"time"
)

// ArtifactOverview represents the scan overview response from Harbor API
type ArtifactOverview struct {
	Components int                    `json:"components"`
	Summary    map[string]interface{} `json:"summary"` // Severity counts
	Scanner    string                 `json:"scanner,omitempty"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities,omitempty"`
}

// Vulnerability represents a single vulnerability finding
type Vulnerability struct {
	Severity     string `json:"severity"`
	VulnerabilityID string `json:"vulnerability_id"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	Description  string `json:"description"`
	Links        []Link `json:"links,omitempty"`
}

// Link represents a related link for a vulnerability
type Link struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Artifact represents an artifact from Harbor API
type Artifact struct {
	Digest      string                 `json:"digest"`
	Tag         string                 `json:"tag"`
	Repository  Repository             `json:"repository"`
	Labels      []Label                `json:"labels,omitempty"`
	Immutable   bool                   `json:"immutable"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
	CreatedAt   time.Time              `json:"creation_time"`
	UpdatedAt   time.Time              `json:"update_time"`
}

// Repository represents a repository in Harbor
type Repository struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	ProjectID   int    `json:"project_id"`
	ProjectName string `json:"project_name"`
}

// Label represents a label on an artifact
type Label struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	Scope       string `json:"scope"`
	ProjectID   int    `json:"project_id"`
	Count       int    `json:"count"`
}

// Project represents a project in Harbor
type Project struct {
	ID                 int                    `json:"project_id"`
	Name               string                 `json:"name"`
	RepoCount          int                    `json:"repo_count"`
	ChartCount         int                    `json:"chart_count"`
	ProjectMemberCount int                    `json:"project_member_count"`
	Public             bool                   `json:"public"`
	RegistryCount      int                    `json:"registry_count"`
	StorageLimit       int64                  `json:"storage_limit"`
	StorageUsed        int64                  `json:"storage_used"`
	Quota              Quota                  `json:"quota"`
	CveAllowlist       CVEAllowlist           `json:"cve_allowlist"`
	Resources          []Resource             `json:"resources"`
	Tags               []Tag                  `json:"tags,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
	OwnerName          string                 `json:"owner_name"`
	CreationTime       time.Time              `json:"creation_time"`
	UpdateTime         time.Time              `json:"update_time"`
	Deleted            bool                   `json:"deleted"`
	TemplateID         int                    `json:"template_id"`
	TemplateVersion    string                 `json:"template_version"`
	EnableContentTrust bool                   `json:"content_trust"`
	ContentTrustPolicy string                 `json:"content_trust_policy"`
	Severity           string                 `json:"severity"`
	ScanAllPolicy      ScanAllPolicy          `json:"scan_all_policy"`
	AdvancedScan       AdvancedScan           `json:"advanced_scan"`
}

// Quota represents project quota
type Quota struct {
	BillInquiry bool `json:"bill_inquiry"`
}

// CVEAllowlist represents CVE allowlist
type CVEAllowlist struct {
	ListID   int    `json:"list_id"`
	ListName string `json:"list_name"`
}

// Resource represents a resource
type Resource struct {
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
}

// Tag represents a tag
type Tag struct {
	TagID      string `json:"tag_id"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
	Author     string `json:"author"`
	Created    string `json:"created"`
	Deleted    bool   `json:"deleted"`
	Signed     bool   `json:"signed"`
	ScanStatus string `json:"scan_status"`
}

// ScanAllPolicy represents scan all policy
type ScanAllPolicy struct {
	Type     string `json:"type"`
	Parameter string `json:"parameter"`
}

// AdvancedScan represents advanced scan settings
type AdvancedScan struct {
	Enabled bool `json:"enabled"`
}

// ScanOverview represents a simplified scan overview for webhook processing
type ScanOverview struct {
	Status    string                 `json:"status"`
	Summary   map[string]int         `json:"summary"` // Severity counts
	Scanner   string                 `json:"scanner"`
	Timestamp time.Time              `json:"timestamp"`
	Findings  []ScanFinding          `json:"findings"`
}

// ScanFinding represents a single scan finding
type ScanFinding struct {
	Severity     string                 `json:"severity"`
	VulnerabilityID string               `json:"vulnerability_id"`
	Package      string                 `json:"package"`
	Version      string                 `json:"version"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Links        []Link                 `json:"links"`
	PrimaryURL   string                 `json:"primary_url"`
}

// WebhookEvent represents a webhook event from Harbor
type WebhookEvent struct {
	Type      string                 `json:"type"`
	OccurAt   int64                  `json:"occur_at"`
	Operator  string                 `json:"operator"`
	EventData map[string]interface{} `json:"event_data"`
}

// ExtractEvent extracts webhook event data into a structured format
func ExtractEvent(data map[string]interface{}) (*WebhookEvent, error) {
	event := &WebhookEvent{}
	
	// Extract basic fields
	if typ, ok := data["type"].(string); ok {
		event.Type = typ
	} else {
		return nil, fmt.Errorf("missing or invalid event type")
	}
	
	if occurAt, ok := data["occur_at"].(float64); ok {
		event.OccurAt = int64(occurAt)
	} else {
		return nil, fmt.Errorf("missing or invalid occur_at")
	}
	
	if operator, ok := data["operator"].(string); ok {
		event.Operator = operator
	}
	
	// Extract event data
	if eventData, ok := data["event_data"].(map[string]interface{}); ok {
		event.EventData = eventData
	} else {
		return nil, fmt.Errorf("missing or invalid event_data")
	}
	
	return event, nil
}

// GetResources extracts resources from event data
func (e *WebhookEvent) GetResources() ([]Resource, error) {
	resources := []Resource{}
	
	if resourcesData, ok := e.EventData["resources"].([]interface{}); ok {
		for _, resourceData := range resourcesData {
			if resource, ok := resourceData.(map[string]interface{}); ok {
				res := Resource{}
				if digest, ok := resource["digest"].(string); ok {
					res.ResourceName = digest
				}
				if tag, ok := resource["tag"].(string); ok {
					res.ResourceName = tag
				}
				if url, ok := resource["resource_url"].(string); ok {
					res.ResourceType = "artifact"
					res.ResourceName = url
				}
				resources = append(resources, res)
			}
		}
	}
	
	return resources, nil
}

// GetRepository extracts repository information from event data
func (e *WebhookEvent) GetRepository() (Repository, error) {
	repo := Repository{}
	
	if repoData, ok := e.EventData["repository"].(map[string]interface{}); ok {
		if id, ok := repoData["project_id"].(float64); ok {
			repo.ProjectID = int(id)
		}
		if name, ok := repoData["name"].(string); ok {
			repo.Name = name
		}
		if namespace, ok := repoData["namespace"].(string); ok {
			repo.ProjectName = namespace
		}
	}
	
	return repo, nil
}

// GetScanOverview extracts scan overview from event data
func (e *WebhookEvent) GetScanOverview() (*ScanOverview, error) {
	overview := &ScanOverview{
		Summary: make(map[string]int),
	}
	
	// Try different possible locations for scan overview data
	if scanOverview, ok := e.EventData["scan_overview"].(map[string]interface{}); ok {
		// New format: scan_overview.summary
		if summary, ok := scanOverview["summary"].(map[string]interface{}); ok {
			for key, value := range summary {
				if count, ok := value.(float64); ok {
					overview.Summary[key] = int(count)
				}
			}
		}
		
		// Try scanner information
		if scanner, ok := scanOverview["scanner"].(string); ok {
			overview.Scanner = scanner
		}
	}
	
	// Try legacy format: scan_overview[scanner_key].summary
	if scanOverview, ok := e.EventData["scan_overview"].(map[string]interface{}); ok {
		for _, value := range scanOverview {
			if scannerData, ok := value.(map[string]interface{}); ok {
				if summary, ok := scannerData["summary"].(map[string]interface{}); ok {
					for severity, count := range summary {
						if c, ok := count.(float64); ok {
							overview.Summary[severity] = int(c)
						}
					}
				}
				if scanner, ok := scannerData["scanner"].(string); ok {
					overview.Scanner = scanner
				}
			}
		}
	}
	
	return overview, nil
}