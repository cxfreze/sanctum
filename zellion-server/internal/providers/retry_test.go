package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"zellion-server/internal/store"
)

// Every routing test uses a fresh store and loopback HTTP servers; no real keys,
// existing state, or external endpoints are read.
func retryTestRoutes(t *testing.T, urls ...string) (*store.Store, store.ClientModel) {
	t.Helper()
	st, err := store.NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	cm := store.ClientModel{MaxOutputTokens: 100}
	for i, u := range urls {
		id := fmt.Sprintf("retry-provider-%d", i)
		_, err := st.UpsertProvider(store.UpstreamProvider{ID: id, Name: id, Protocol: "openai", BaseURL: u, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		cm.Routes = append(cm.Routes, store.ModelRoute{ProviderID: id, UpstreamModel: fmt.Sprintf("model-%d", i), Priority: i, Weight: 100})
	}
	return st, cm
}

func TestRoutedRetryTransientHTTP(t *testing.T) {
	for _, status := range []int{502, 503, 504} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) < 3 {
					http.Error(w, "temporary", status)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
			}))
			defer srv.Close()
			st, cm := retryTestRoutes(t, srv.URL)
			var text strings.Builder
			result, err := ExecuteRoutedChat(context.Background(), st, cm, ChatRequest{}, StreamCallbacks{OnTextDelta: func(s string) { text.WriteString(s) }})
			if err != nil || calls.Load() != 3 || text.String() != "ok" || result.ProviderID != "retry-provider-0" {
				t.Fatalf("calls=%d text=%q result=%+v err=%v", calls.Load(), text.String(), result, err)
			}
		})
	}
}

func TestRoutedRetryBoundAndLastFailure(t *testing.T) {
	var first, second atomic.Int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { first.Add(1); http.Error(w, "unavailable", 503) }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { second.Add(1); http.Error(w, "bad gateway", 502) }))
	defer b.Close()
	st, cm := retryTestRoutes(t, a.URL, b.URL)
	result, err := ExecuteRoutedChat(context.Background(), st, cm, ChatRequest{}, StreamCallbacks{})
	if err == nil || first.Load() != 3 || second.Load() != 3 || result.ProviderID != "retry-provider-1" || result.UpstreamModel != "model-1" || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("first=%d second=%d result=%+v err=%v", first.Load(), second.Load(), result, err)
	}
}

func TestRoutedNoRetryOtherHTTPStatus(t *testing.T) {
	for _, status := range []int{400, 401, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				http.Error(w, "not retryable HTTP 503", status)
			}))
			defer srv.Close()
			st, cm := retryTestRoutes(t, srv.URL)
			_, err := ExecuteRoutedChat(context.Background(), st, cm, ChatRequest{}, StreamCallbacks{})
			if err == nil || calls.Load() != 1 {
				t.Fatalf("calls=%d err=%v", calls.Load(), err)
			}
		})
	}
	// A similar-looking message is not an explicit HTTP status.
	if isRetryableUpstreamError(errors.New("HTTP 503: unavailable")) {
		t.Fatal("string error classified as retryable")
	}
	if !isRetryableUpstreamError(fmt.Errorf("wrapped: %w", &UpstreamHTTPError{StatusCode: 503})) {
		t.Fatal("wrapped status not recognized")
	}
}

func TestRoutedRetryCancellation(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "unavailable", 503) }))
	defer srv.Close()
	st, cm := retryTestRoutes(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result, err := ExecuteRoutedChat(ctx, st, cm, ChatRequest{}, StreamCallbacks{})
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 || result.ProviderID != "retry-provider-0" {
		t.Fatalf("calls=%d result=%+v err=%v", calls.Load(), result, err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, err = ExecuteRoutedChat(ctx2, st, cm, ChatRequest{}, StreamCallbacks{})
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("pre-cancelled calls=%d err=%v", calls.Load(), err)
	}
}

func TestRoutedOutputPreventsFailoverAndPreservesUsage(t *testing.T) {
	chunks := map[string]string{
		"text":     `{"choices":[{"delta":{"content":"partial"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`,
		"thinking": `{"choices":[{"delta":{"reasoning_content":"partial"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`,
		"tool":     `{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-1","function":{"name":"lookup","arguments":"{}"}}]}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`,
		"usage":    `{"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}`,
	}
	for name, chunk := range chunks {
		t.Run(name, func(t *testing.T) {
			var first, second atomic.Int32
			a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				first.Add(1)
				// A short response relative to Content-Length causes a real transport error
				// after the parser has consumed the valid callback-producing SSE frame.
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Length", "100000")
				fmt.Fprintf(w, "data: %s\n\n", chunk)
			}))
			defer a.Close()
			b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { second.Add(1); http.Error(w, "must not be reached", 503) }))
			defer b.Close()
			st, cm := retryTestRoutes(t, a.URL, b.URL)
			result, err := ExecuteRoutedChat(context.Background(), st, cm, ChatRequest{}, StreamCallbacks{})
			if err == nil || first.Load() != 1 || second.Load() != 0 || result.ProviderID != "retry-provider-0" || result.PromptTokens != 7 || result.CompletionTokens != 3 {
				t.Fatalf("first=%d second=%d result=%+v err=%v", first.Load(), second.Load(), result, err)
			}
		})
	}
}
