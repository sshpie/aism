package cisco

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const webexAPIBase = "https://webexapis.com/v1"

// WebexClient sends tiptoe assessment summaries to a Cisco Webex room.
type WebexClient struct {
	Token  string
	RoomID string
	client *http.Client
}

// ─── Adaptive Card types ────────────────────────────────────────────────────

type acTextBlock struct {
	Type   string `json:"type"`
	Text   string `json:"text"`
	Weight string `json:"weight,omitempty"`
	Size   string `json:"size,omitempty"`
	Wrap   bool   `json:"wrap,omitempty"`
	Color  string `json:"color,omitempty"`
}

type acFact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

type acFactSet struct {
	Type  string   `json:"type"`
	Facts []acFact `json:"facts"`
}

type acSubmitAction struct {
	Type  string         `json:"type"`
	Title string         `json:"title"`
	Data  map[string]any `json:"data,omitempty"`
	Style string         `json:"style,omitempty"`
}

type adaptiveCard struct {
	Schema  string `json:"$schema"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Body    []any  `json:"body"`
	Actions []any  `json:"actions"`
}

type webexAttachment struct {
	ContentType string       `json:"contentType"`
	Content     adaptiveCard `json:"content"`
}

type webexCardMessage struct {
	RoomID      string            `json:"roomId"`
	Markdown    string            `json:"markdown"` // fallback for clients without card support
	Attachments []webexAttachment `json:"attachments"`
}

// ActionEvent is the payload retrieved from GET /attachment/actions/{id}
// after a card button webhook fires.
type ActionEvent struct {
	ID        string         `json:"id"`
	MessageID string         `json:"messageId"`
	PersonID  string         `json:"personId"`
	RoomID    string         `json:"roomId"`
	Type      string         `json:"type"`
	Inputs    map[string]any `json:"inputs"`
}

// WebhookRegistration is the response body from POST /webhooks.
type WebhookRegistration struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	TargetURL string `json:"targetUrl"`
	Resource  string `json:"resource"`
	Event     string `json:"event"`
	Status    string `json:"status"`
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

func (w *WebexClient) post(path string, payload any) (*http.Response, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", webexAPIBase+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.Token)
	req.Header.Set("Content-Type", "application/json")
	return w.client.Do(req)
}

// Notify posts a plain-text tiptoe assessment summary to the configured Webex room.
// For a richer structured card with action buttons, use NotifyCard.
func (w *WebexClient) Notify(target, ip string, services []string, blocked bool) error {
	md := formatMarkdown(target, ip, services, blocked)
	resp, err := w.post("/messages", webexMessage{RoomID: w.RoomID, Markdown: md})
	if err != nil {
		return fmt.Errorf("webex: post message: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("webex: message returned %d", resp.StatusCode)
	}
	return nil
}

// NotifyCard posts an Adaptive Card to the Webex room for a single finding.
// The card includes a structured fact set and two action buttons — Acknowledge
// and Isolate — whose click events are delivered via the attachmentActions
// webhook. Register one with RegisterActionWebhook; retrieve the submitted
// data with GetAttachmentAction.
//
// Required bot scope: spark:messages_write
// Webhook scope:      spark:all (for webhook registration)
func (w *WebexClient) NotifyCard(target, ip, platform, family string, port int, noAuth bool) error {
	authLabel := "required"
	if noAuth {
		authLabel = "none (open)"
	}
	portStr := fmt.Sprintf("%d", port)
	if port == 0 {
		portStr = "unknown"
	}

	heading := acTextBlock{
		Type:   "TextBlock",
		Text:   "Shadow AI Detected",
		Weight: "Bolder",
		Size:   "Medium",
	}
	subhead := acTextBlock{
		Type:  "TextBlock",
		Text:  fmt.Sprintf("Unauthorized AI/ML service on `%s`", target),
		Wrap:  true,
		Color: "Attention",
	}
	facts := acFactSet{
		Type: "FactSet",
		Facts: []acFact{
			{Title: "Host", Value: target},
			{Title: "IP", Value: ip},
			{Title: "Platform", Value: platform},
			{Title: "Family", Value: family},
			{Title: "Port", Value: portStr},
			{Title: "Auth", Value: authLabel},
		},
	}
	card := adaptiveCard{
		Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
		Type:    "AdaptiveCard",
		Version: "1.0",
		Body:    []any{heading, subhead, facts},
		Actions: []any{
			acSubmitAction{
				Type:  "Action.Submit",
				Title: "Acknowledge",
				Style: "positive",
				Data:  map[string]any{"action": "acknowledge", "ip": ip, "platform": platform},
			},
			acSubmitAction{
				Type:  "Action.Submit",
				Title: "Isolate",
				Style: "destructive",
				Data:  map[string]any{"action": "isolate", "ip": ip, "platform": platform},
			},
		},
	}
	fallbackMD := fmt.Sprintf("**tiptoe** — shadow AI detected: **%s** on `%s` (port %s)", platform, target, portStr)
	msg := webexCardMessage{
		RoomID:   w.RoomID,
		Markdown: fallbackMD,
		Attachments: []webexAttachment{{
			ContentType: "application/vnd.microsoft.card.adaptive",
			Content:     card,
		}},
	}
	resp, err := w.post("/messages", msg)
	if err != nil {
		return fmt.Errorf("webex: post card: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("webex: card returned %d", resp.StatusCode)
	}
	return nil
}

// RegisterActionWebhook creates a Webex webhook that fires when a user clicks
// an action button on an Adaptive Card posted by this bot. targetURL receives
// a POST with the action event — call GetAttachmentAction(event.id) to retrieve
// the encrypted form data.
//
// Idempotent by name: if a webhook named "tiptoe-card-actions" already exists,
// the API will create a second one. List and deduplicate if needed.
//
// Required scope: spark:all
func (w *WebexClient) RegisterActionWebhook(targetURL string) (*WebhookRegistration, error) {
	payload := map[string]string{
		"name":      "tiptoe-card-actions",
		"targetUrl": targetURL,
		"resource":  "attachmentActions",
		"event":     "created",
	}
	resp, err := w.post("/webhooks", payload)
	if err != nil {
		return nil, fmt.Errorf("webex: register webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("webex: register webhook: HTTP %d", resp.StatusCode)
	}
	var reg WebhookRegistration
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil, fmt.Errorf("webex: register webhook: decode: %w", err)
	}
	return &reg, nil
}

// GetAttachmentAction retrieves the form data submitted when a user clicked a
// card action button. Call this after receiving an attachmentActions webhook
// notification — the notification itself carries no payload (data is encrypted).
//
// Required scope: spark:all
func (w *WebexClient) GetAttachmentAction(actionID string) (*ActionEvent, error) {
	req, err := http.NewRequest("GET", webexAPIBase+"/attachment/actions/"+actionID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webex: get action: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("webex: get action: HTTP %d: %s", resp.StatusCode, body)
	}
	var ev ActionEvent
	if err := json.NewDecoder(resp.Body).Decode(&ev); err != nil {
		return nil, fmt.Errorf("webex: get action: decode: %w", err)
	}
	return &ev, nil
}

// NotifySummary posts a catalog-run summary to the Webex room.
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
	resp, err := w.post("/messages", webexMessage{RoomID: w.RoomID, Markdown: sb.String()})
	if err != nil {
		return fmt.Errorf("webex: post summary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("webex: summary returned %d", resp.StatusCode)
	}
	return nil
}

// PostThreadReply posts a follow-up message to an existing message thread.
// Use this after taking containment actions (ISE ANC, Secure Endpoint isolation)
// to update the original finding card without flooding the room.
//
// parentID is the messageId of the card posted by NotifyCard.
func (w *WebexClient) PostThreadReply(parentID, markdown string) error {
	payload := map[string]string{
		"roomId":   w.RoomID,
		"parentId": parentID,
		"markdown": markdown,
	}
	resp, err := w.post("/messages", payload)
	if err != nil {
		return fmt.Errorf("webex: thread reply: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("webex: thread reply: HTTP %d", resp.StatusCode)
	}
	return nil
}

// EnsureRoom returns the roomId for a space named title, creating it if it
// does not exist. Use to automatically provision a "tiptoe-alerts" space when
// the operator does not supply --webex-room.
func (w *WebexClient) EnsureRoom(title string) (roomID string, err error) {
	// list spaces, find by title
	req, err := http.NewRequest("GET", webexAPIBase+"/rooms?max=200", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+w.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("webex: list rooms: %w", err)
	}
	defer resp.Body.Close()

	var rooms struct {
		Items []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rooms); err != nil {
		return "", fmt.Errorf("webex: list rooms: decode: %w", err)
	}
	for _, r := range rooms.Items {
		if r.Title == title {
			return r.ID, nil
		}
	}

	// create new space
	createResp, err := w.post("/rooms", map[string]string{"title": title})
	if err != nil {
		return "", fmt.Errorf("webex: create room: %w", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != 200 {
		return "", fmt.Errorf("webex: create room: HTTP %d", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		return "", fmt.Errorf("webex: create room: decode: %w", err)
	}
	return created.ID, nil
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
