package management

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type batchCheckExecutor struct {
	provider string
	handler  func(*http.Request) (*http.Response, error)
}

func (e *batchCheckExecutor) Identifier() string { return e.provider }

func (e *batchCheckExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *batchCheckExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *batchCheckExecutor) Refresh(context.Context, *coreauth.Auth) (*coreauth.Auth, error) {
	return nil, nil
}

func (e *batchCheckExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *batchCheckExecutor) HttpRequest(_ context.Context, auth *coreauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, nil
	}
	if e.handler != nil {
		return e.handler(req)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

func (e *batchCheckExecutor) PrepareRequest(req *http.Request, auth *coreauth.Auth) error {
	if req == nil || auth == nil {
		return nil
	}
	req.Header.Set("X-Auth-ID", auth.ID)
	return nil
}

func newBatchCheckHandler(t *testing.T) *Handler {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := coreauth.NewManager(&memoryAuthStore{items: map[string]*coreauth.Auth{}}, nil, nil)
	manager.RegisterExecutor(&batchCheckExecutor{provider: "gemini"})
	manager.RegisterExecutor(&batchCheckExecutor{provider: "claude"})
	return &Handler{authManager: manager}
}

func registerAuthForBatchCheck(t *testing.T, h *Handler, auth *coreauth.Auth) *coreauth.Auth {
	t.Helper()
	if _, err := h.authManager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	stored, ok := h.authManager.GetByID(auth.ID)
	if !ok {
		t.Fatalf("registered auth %q not found", auth.ID)
	}
	stored.EnsureIndex()
	return stored
}

func TestBatchCheckAuthFiles_SuccessAndStatusUpdate(t *testing.T) {
	t.Parallel()

	h := newBatchCheckHandler(t)
	h.authManager.RegisterExecutor(&batchCheckExecutor{
		provider: "gemini",
		handler: func(req *http.Request) (*http.Response, error) {
			if got := req.URL.String(); got != "https://generativelanguage.googleapis.com/v1beta/models" {
				t.Fatalf("probe url = %s", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"X-Test": []string{"ok"}},
				Body:       io.NopCloser(strings.NewReader(`{"models":[]}`)),
				Request:    req,
			}, nil
		},
	})

	auth := registerAuthForBatchCheck(t, h, &coreauth.Auth{
		ID:       "gemini-auth.json",
		Provider: "gemini",
		FileName: "gemini-auth.json",
		Status:   coreauth.StatusUnknown,
	})

	body := map[string]any{
		"auth_indexes":  []string{auth.Index},
		"update_status": true,
	}
	payload, _ := json.Marshal(body)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/check", bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.BatchCheckAuthFiles(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp struct {
		Items []batchAPICallResult `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("items len = %d, want 1", len(resp.Items))
	}
	if resp.Items[0].Status != "ok" {
		t.Fatalf("item status = %q, want ok", resp.Items[0].Status)
	}

	updated, ok := h.authManager.GetByID(auth.ID)
	if !ok {
		t.Fatalf("updated auth %q not found", auth.ID)
	}
	if updated.Status != coreauth.StatusActive {
		t.Fatalf("auth status = %q, want %q", updated.Status, coreauth.StatusActive)
	}
	if updated.Unavailable {
		t.Fatal("expected auth unavailable to be false")
	}
	if updated.LastRefreshedAt.IsZero() {
		t.Fatal("expected last_refreshed_at to be set")
	}
}

func TestBatchCheckAuthFiles_PartialFailure(t *testing.T) {
	t.Parallel()

	h := newBatchCheckHandler(t)
	h.authManager.RegisterExecutor(&batchCheckExecutor{
		provider: "claude",
		handler: func(req *http.Request) (*http.Response, error) {
			statusCode := http.StatusOK
			body := `{"data":[]}`
			if req.Header.Get("X-Auth-ID") == "claude-bad.json" {
				statusCode = http.StatusUnauthorized
				body = `{"error":"unauthorized"}`
			}
			return &http.Response{
				StatusCode: statusCode,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    req,
			}, nil
		},
	})

	good := registerAuthForBatchCheck(t, h, &coreauth.Auth{ID: "claude-good.json", Provider: "claude", FileName: "claude-good.json"})
	bad := registerAuthForBatchCheck(t, h, &coreauth.Auth{ID: "claude-bad.json", Provider: "claude", FileName: "claude-bad.json"})

	body := map[string]any{
		"auth_indexes":  []string{good.Index, bad.Index},
		"update_status": true,
	}
	payload, _ := json.Marshal(body)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/check", bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.BatchCheckAuthFiles(ctx)

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusMultiStatus)
	}

	updatedGood, _ := h.authManager.GetByID(good.ID)
	if updatedGood.Status != coreauth.StatusActive {
		t.Fatalf("good auth status = %q, want %q", updatedGood.Status, coreauth.StatusActive)
	}
	updatedBad, _ := h.authManager.GetByID(bad.ID)
	if updatedBad.Status != coreauth.StatusError {
		t.Fatalf("bad auth status = %q, want %q", updatedBad.Status, coreauth.StatusError)
	}
	if !updatedBad.Unavailable {
		t.Fatal("expected bad auth unavailable to be true")
	}
	if !strings.Contains(updatedBad.StatusMessage, "401") {
		t.Fatalf("bad auth status message = %q, want contains 401", updatedBad.StatusMessage)
	}
}

func TestBatchCheckAuthFiles_IncludeAll(t *testing.T) {
	t.Parallel()

	h := newBatchCheckHandler(t)
	registerAuthForBatchCheck(t, h, &coreauth.Auth{ID: "gemini-1.json", Provider: "gemini", FileName: "gemini-1.json"})
	registerAuthForBatchCheck(t, h, &coreauth.Auth{ID: "claude-1.json", Provider: "claude", FileName: "claude-1.json"})

	body := map[string]any{
		"include_all": true,
	}
	payload, _ := json.Marshal(body)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/check", bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.BatchCheckAuthFiles(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp struct {
		Items []batchAPICallResult `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("items len = %d, want 2", len(resp.Items))
	}
}
