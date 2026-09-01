package cisco

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// XDRClient submits threat observables to Cisco XDR via the CTIM bundle API.
// It uses OAuth2 client credentials to obtain a bearer token automatically.
type XDRClient struct {
	ClientID     string
	ClientSecret string
	Region       string // "us" | "eu" | "apjc"
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

// NewXDRClient returns an XDRClient. Region defaults to "us" if empty.
func NewXDRClient(clientID, clientSecret, region string) *XDRClient {
	if region == "" {
		region = "us"
	}
	return &XDRClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Region:       region,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *XDRClient) visibilityBase() string {
	switch c.Region {
	case "eu":
		return "https://visibility.eu.amp.cisco.com"
	case "apjc":
		return "https://visibility.apjc.amp.cisco.com"
	default:
		return "https://visibility.amp.cisco.com"
	}
}

type xdrTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func (c *XDRClient) authenticate() error {
	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.ClientID)
	data.Set("client_secret", c.ClientSecret)

	resp, err := c.client.PostForm(c.visibilityBase()+"/iroh/oauth2/token", data)
	if err != nil {
		return fmt.Errorf("xdr: auth: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("xdr: auth returned %d", resp.StatusCode)
	}
	var tr xdrTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return fmt.Errorf("xdr: decode token: %w", err)
	}
	c.token = tr.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn-30) * time.Second)
	return nil
}

// Sighting is one aism finding to be submitted to Cisco XDR as a CTIM sighting.
type Sighting struct {
	IP       string   // target IP address
	Services []string // human-readable service strings, e.g. "ollama :11434 VERIFIED_UNAUTH"
	ScanTime string   // RFC3339 timestamp of the assessment
}

// SubmitSightings creates a CTIM bundle containing a sighting for each finding
// and imports it into Cisco XDR.
func (c *XDRClient) SubmitSightings(sightings []Sighting) error {
	if len(sightings) == 0 {
		return nil
	}
	if err := c.authenticate(); err != nil {
		return err
	}

	bundle := c.buildBundle(sightings)
	body, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("xdr: marshal bundle: %w", err)
	}

	req, err := http.NewRequest("POST",
		c.visibilityBase()+"/iroh/iroh-intel/bundle/import",
		strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("xdr: submit bundle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("xdr: bundle import returned %d", resp.StatusCode)
	}
	return nil
}

// ctimObservable is a CTIM observable (IP, domain, etc.).
type ctimObservable struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ctimObservedTime is the CTIM time window for a sighting.
type ctimObservedTime struct {
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
}

// ctimSighting is a CTIM sighting entity.
type ctimSighting struct {
	Type          string           `json:"type"`
	SchemaVersion string           `json:"schema_version"`
	Source        string           `json:"source"`
	Title         string           `json:"title"`
	Description   string           `json:"description"`
	Confidence    string           `json:"confidence"`
	Count         int              `json:"count"`
	ObservedTime  ctimObservedTime `json:"observed_time"`
	Observables   []ctimObservable `json:"observables"`
}

type ctimBundle struct {
	Type      string         `json:"type"`
	Source    string         `json:"source"`
	Sightings []ctimSighting `json:"sightings"`
}

func (c *XDRClient) buildBundle(sightings []Sighting) ctimBundle {
	var ss []ctimSighting
	for _, s := range sightings {
		ts := s.ScanTime
		if ts == "" {
			ts = time.Now().UTC().Format(time.RFC3339)
		}
		ss = append(ss, ctimSighting{
			Type:          "sighting",
			SchemaVersion: "1.0.22",
			Source:        "aism",
			Title:         fmt.Sprintf("Shadow AI/ML services on %s", s.IP),
			Description: fmt.Sprintf(
				"aism detected unauthenticated AI/ML services: %s",
				strings.Join(s.Services, "; ")),
			Confidence:  "High",
			Count:       1,
			ObservedTime: ctimObservedTime{StartTime: ts, EndTime: ts},
			Observables:  []ctimObservable{{Type: "ip", Value: s.IP}},
		})
	}
	return ctimBundle{
		Type:      "bundle",
		Source:    "aism",
		Sightings: ss,
	}
}
