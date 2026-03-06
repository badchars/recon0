package cdp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
)

// HAR 1.2 types

type HAR struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
	Timings         HARTimings  `json:"timings"`
	ServerIPAddress string      `json:"serverIPAddress,omitempty"`
}

type HARRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	QueryString []HARQuery  `json:"queryString"`
	PostData    *HARPost    `json:"postData,omitempty"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type HARResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	Content     HARContent  `json:"content"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
	RedirectURL string      `json:"redirectURL,omitempty"`
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARQuery struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type HARTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// HARBuilder collects CDP network events and builds a HAR file.
type HARBuilder struct {
	mu       sync.Mutex
	pending  map[network.RequestID]*pendingEntry
	complete []HAREntry
}

type pendingEntry struct {
	startTime time.Time
	request   HARRequest
}

// NewHARBuilder creates a new HAR builder.
func NewHARBuilder() *HARBuilder {
	return &HARBuilder{
		pending: make(map[network.RequestID]*pendingEntry),
	}
}

// OnRequestWillBeSent handles Network.requestWillBeSent events.
func (hb *HARBuilder) OnRequestWillBeSent(ev *network.EventRequestWillBeSent) {
	hb.mu.Lock()
	defer hb.mu.Unlock()

	req := ev.Request

	headers := headersToHAR(req.Headers)

	harReq := HARRequest{
		Method:      req.Method,
		URL:         req.URL,
		HTTPVersion: "HTTP/1.1",
		Headers:     headers,
		QueryString: []HARQuery{},
		HeadersSize: -1,
		BodySize:    -1,
	}

	if req.HasPostData && len(req.PostDataEntries) > 0 {
		var body string
		for _, entry := range req.PostDataEntries {
			body += entry.Bytes
		}
		harReq.PostData = &HARPost{
			MimeType: headerValue(headers, "Content-Type"),
			Text:     body,
		}
		harReq.BodySize = len(body)
	}

	hb.pending[ev.RequestID] = &pendingEntry{
		startTime: time.Now(),
		request:   harReq,
	}
}

// OnResponseReceived handles Network.responseReceived events.
func (hb *HARBuilder) OnResponseReceived(ev *network.EventResponseReceived) {
	hb.mu.Lock()
	defer hb.mu.Unlock()

	entry, ok := hb.pending[ev.RequestID]
	if !ok {
		return
	}

	resp := ev.Response
	headers := headersToHAR(resp.Headers)
	elapsed := time.Since(entry.startTime).Milliseconds()

	timings := HARTimings{Send: -1, Wait: -1, Receive: -1}
	if resp.Timing != nil {
		timings.Send = resp.Timing.SendStart
		timings.Wait = resp.Timing.ReceiveHeadersEnd - resp.Timing.SendEnd
		timings.Receive = 0
	}

	harEntry := HAREntry{
		StartedDateTime: entry.startTime.UTC().Format(time.RFC3339Nano),
		Time:            float64(elapsed),
		Request:         entry.request,
		Response: HARResponse{
			Status:      int(resp.Status),
			StatusText:  resp.StatusText,
			HTTPVersion: resp.Protocol,
			Headers:     headers,
			Content: HARContent{
				Size:     int(resp.EncodedDataLength),
				MimeType: resp.MimeType,
			},
			HeadersSize: -1,
			BodySize:    int(resp.EncodedDataLength),
		},
		Timings:         timings,
		ServerIPAddress: resp.RemoteIPAddress,
	}

	hb.complete = append(hb.complete, harEntry)
	delete(hb.pending, ev.RequestID)
}

// OnLoadingFailed handles Network.loadingFailed events.
func (hb *HARBuilder) OnLoadingFailed(ev *network.EventLoadingFailed) {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	delete(hb.pending, ev.RequestID)
}

// EntryCount returns the number of completed HAR entries.
func (hb *HARBuilder) EntryCount() int {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	return len(hb.complete)
}

// Build constructs the final HAR object.
func (hb *HARBuilder) Build() *HAR {
	hb.mu.Lock()
	defer hb.mu.Unlock()

	return &HAR{
		Log: HARLog{
			Version: "1.2",
			Creator: HARCreator{
				Name:    "recon0",
				Version: "1.0",
			},
			Entries: hb.complete,
		},
	}
}

// WriteToFile writes the HAR to a JSON file.
func (hb *HARBuilder) WriteToFile(path string) error {
	har := hb.Build()

	os.MkdirAll(filepath.Dir(path), 0755)

	data, err := json.MarshalIndent(har, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal HAR: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// URLs returns all unique URLs captured in the HAR.
func (hb *HARBuilder) URLs() []string {
	hb.mu.Lock()
	defer hb.mu.Unlock()

	seen := make(map[string]bool)
	var urls []string
	for _, e := range hb.complete {
		if !seen[e.Request.URL] {
			seen[e.Request.URL] = true
			urls = append(urls, e.Request.URL)
		}
	}
	return urls
}

// JSURLs returns URLs of JavaScript resources from the HAR entries.
func (hb *HARBuilder) JSURLs() []string {
	hb.mu.Lock()
	defer hb.mu.Unlock()

	seen := make(map[string]bool)
	var urls []string
	for _, e := range hb.complete {
		ct := e.Response.Content.MimeType
		if isJSMimeType(ct) && !seen[e.Request.URL] {
			seen[e.Request.URL] = true
			urls = append(urls, e.Request.URL)
		}
	}
	return urls
}

func isJSMimeType(ct string) bool {
	switch ct {
	case "application/javascript", "text/javascript",
		"application/x-javascript", "application/ecmascript",
		"text/ecmascript":
		return true
	}
	return false
}

func headersToHAR(h network.Headers) []HARHeader {
	result := make([]HARHeader, 0, len(h))
	for name, value := range h {
		result = append(result, HARHeader{
			Name:  name,
			Value: fmt.Sprintf("%v", value),
		})
	}
	return result
}

func headerValue(headers []HARHeader, name string) string {
	for _, h := range headers {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}
