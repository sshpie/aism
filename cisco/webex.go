package cisco

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// WebexClient sends tiptoe assessment summaries to a Cisco Webex room.
type WebexClient struct {
	Token  string
	RoomID string
	client *http.Client
}

// NewWebexClient returns a WebexClient ready to post messages.
func NewWebexClient(token, roomID string) *WebexClient {
	return &WebexClient{
		Token:  token,
		RoomID: roomID,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

type webexMessage struct {
	RoomID   string `json:"roomId"`
	Markdown string `json:"markdown"`
}

// Notify posts a tiptoe assessment summary to the configured Webex room.
// services is the list of AI/ML services found (empty if none). blocked
// indicates the host filtered the scan before completion.
func (w *WebexClient) Notify(target, ip string, services []string, blocked bool) error {
	md := formatMarkdown(target, ip, services, blocked)
	msg := webexMessage{RoomID: w.RoomID, Markdown: md}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("webex: marshal message: %w", err)
	}

	req, err := http.NewRequest("POST", "https://webexapis.com/v1/messages",
		strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webex: post message: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("webex: message returned %d", resp.StatusCode)
	}
	return nil
}

// NotifySummary posts a catalog-run summary to the Webex room — total devices
// scanned, how many had findings, and the list of flagged IPs.
func (w *WebexClient) NotifySummary(total, withFindings int, flagged []string) error {
	var sb strings.Builder
	sb.WriteString("**tiptoe catalog complete**\n\n")
	sb.WriteString(fmt.Sprintf("Scanned **%d** managed devices — ", total))
	if withFindings == 0 {
		sb.WriteString("no shadow AI/ML services found.\n")
	} else {
		sb.WriteString(fmt.Sprintf("**%d** device(s) with unauth AI/ML services:\n\n", withFindings))
		for _, ip := range flagged {
			sb.WriteString(fmt.Sprintf("- `%s`\n", ip))
		}
	}
	msg := webexMessage{RoomID: w.RoomID, Markdown: sb.String()}
	body, _ := json.Marshal(msg)
	req, err := http.NewRequest("POST", "https://webexapis.com/v1/messages",
		strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webex: post summary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("webex: summary returned %d", resp.StatusCode)
	}
	return nil
}

func formatMarkdown(target, ip string, services []string, blocked bool) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**tiptoe** — `%s`", target))
	if ip != "" && ip != target {
		sb.WriteString(fmt.Sprintf(" (`%s`)", ip))
	}
	sb.WriteString("\n\n")
	if len(services) > 0 {
		sb.WriteString("**Shadow AI/ML services detected:**\n")
		for _, s := range services {
			sb.WriteString(fmt.Sprintf("- %s\n", s))
		}
	} else {
		sb.WriteString("No AI/ML services detected.\n")
	}
	if blocked {
		sb.WriteString("\n> Scan was blocked mid-run — results may be partial.\n")
	}
	return sb.String()
}
