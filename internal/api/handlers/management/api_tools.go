package management

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/geminicli"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const defaultAPICallTimeout = 60 * time.Second

const (
	geminiOAuthClientID     = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
	geminiOAuthClientSecret = "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"
)

var geminiOAuthScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

const (
	antigravityOAuthClientID     = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
	antigravityOAuthClientSecret = "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"
)

var antigravityOAuthTokenURL = "https://oauth2.googleapis.com/token"

type apiCallRequest struct {
	AuthIndexSnake  *string           `json:"auth_index"`
	AuthIndexCamel  *string           `json:"authIndex"`
	AuthIndexPascal *string           `json:"AuthIndex"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Header          map[string]string `json:"header"`
	Data            string            `json:"data"`
}

type apiCallResponse struct {
	StatusCode int                 `json:"status_code"`
	Header     map[string][]string `json:"header"`
	Body       string              `json:"body"`
}

type batchAPICallItem struct {
	Name            string            `json:"name,omitempty"`
	AuthIndexSnake  *string           `json:"auth_index,omitempty"`
	AuthIndexCamel  *string           `json:"authIndex,omitempty"`
	AuthIndexPascal *string           `json:"AuthIndex,omitempty"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Header          map[string]string `json:"header,omitempty"`
	Data            string            `json:"data,omitempty"`
	UpdateStatus    bool              `json:"update_status,omitempty"`
}

type batchAPICallRequest struct {
	Items []batchAPICallItem `json:"items"`
}

type batchAPICallResult struct {
	Name       string              `json:"name,omitempty"`
	AuthIndex  string              `json:"auth_index,omitempty"`
	Status     string              `json:"status"`
	Error      string              `json:"error,omitempty"`
	StatusCode int                 `json:"status_code,omitempty"`
	Header     map[string][]string `json:"header,omitempty"`
	Body       string              `json:"body,omitempty"`
}

type batchAuthCheckRequest struct {
	AuthIndexes  []string `json:"auth_indexes,omitempty"`
	Names        []string `json:"names,omitempty"`
	IncludeAll   bool     `json:"include_all,omitempty"`
	UpdateStatus bool     `json:"update_status,omitempty"`
}

// APICall makes a generic HTTP request on behalf of the management API caller.
// It is protected by the management middleware.
//
// Endpoint:
//
//	POST /v0/management/api-call
//
// Authentication:
//
//	Same as other management APIs (requires a management key and remote-management rules).
//	You can provide the key via:
//	- Authorization: Bearer <key>
//	- X-Management-Key: <key>
//
// Request JSON:
//   - auth_index / authIndex / AuthIndex (optional):
//     The credential "auth_index" from GET /v0/management/auth-files (or other endpoints returning it).
//     If omitted or not found, credential-specific proxy/token substitution is skipped.
//   - method (required): HTTP method, e.g. GET, POST, PUT, PATCH, DELETE.
//   - url (required): Absolute URL including scheme and host, e.g. "https://api.example.com/v1/ping".
//   - header (optional): Request headers map.
//     Supports magic variable "$TOKEN$" which is replaced using the selected credential:
//     1) metadata.access_token
//     2) attributes.api_key
//     3) metadata.token / metadata.id_token / metadata.cookie
//     Example: {"Authorization":"Bearer $TOKEN$"}.
//     Note: if you need to override the HTTP Host header, set header["Host"].
//   - data (optional): Raw request body as string (useful for POST/PUT/PATCH).
//
// Proxy selection (highest priority first):
//  1. Selected credential proxy_url
//  2. Global config proxy-url
//  3. Direct connect (environment proxies are not used)
//
// Response JSON (returned with HTTP 200 when the APICall itself succeeds):
//   - status_code: Upstream HTTP status code.
//   - header: Upstream response headers.
//   - body: Upstream response body as string.
//
// Example:
//
//	curl -sS -X POST "http://127.0.0.1:8317/v0/management/api-call" \
//	  -H "Authorization: Bearer <MANAGEMENT_KEY>" \
//	  -H "Content-Type: application/json" \
//	  -d '{"auth_index":"<AUTH_INDEX>","method":"GET","url":"https://api.example.com/v1/ping","header":{"Authorization":"Bearer $TOKEN$"}}'
//
//	curl -sS -X POST "http://127.0.0.1:8317/v0/management/api-call" \
//	  -H "Authorization: Bearer 831227" \
//	  -H "Content-Type: application/json" \
//	  -d '{"auth_index":"<AUTH_INDEX>","method":"POST","url":"https://api.example.com/v1/fetchAvailableModels","header":{"Authorization":"Bearer $TOKEN$","Content-Type":"application/json","User-Agent":"cliproxyapi"},"data":"{}"}'
func (h *Handler) APICall(c *gin.Context) {
	var body apiCallRequest
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	method := strings.ToUpper(strings.TrimSpace(body.Method))
	if method == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing method"})
		return
	}

	urlStr := strings.TrimSpace(body.URL)
	if urlStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing url"})
		return
	}
	parsedURL, errParseURL := url.Parse(urlStr)
	if errParseURL != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid url"})
		return
	}

	authIndex := firstNonEmptyString(body.AuthIndexSnake, body.AuthIndexCamel, body.AuthIndexPascal)
	auth := h.authByIndex(authIndex)

	reqHeaders := body.Header
	if reqHeaders == nil {
		reqHeaders = map[string]string{}
	}

	var hostOverride string
	var token string
	var tokenResolved bool
	var tokenErr error
	for key, value := range reqHeaders {
		if !strings.Contains(value, "$TOKEN$") {
			continue
		}
		if !tokenResolved {
			token, tokenErr = h.resolveTokenForAuth(c.Request.Context(), auth)
			tokenResolved = true
		}
		if auth != nil && token == "" {
			if tokenErr != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "auth token refresh failed"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "auth token not found"})
			return
		}
		if token == "" {
			continue
		}
		reqHeaders[key] = strings.ReplaceAll(value, "$TOKEN$", token)
	}

	var requestBody io.Reader
	if body.Data != "" {
		requestBody = strings.NewReader(body.Data)
	}

	req, errNewRequest := http.NewRequestWithContext(c.Request.Context(), method, urlStr, requestBody)
	if errNewRequest != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to build request"})
		return
	}

	for key, value := range reqHeaders {
		if strings.EqualFold(key, "host") {
			hostOverride = strings.TrimSpace(value)
			continue
		}
		req.Header.Set(key, value)
	}
	if hostOverride != "" {
		req.Host = hostOverride
	}

	httpClient := &http.Client{
		Timeout: defaultAPICallTimeout,
	}
	httpClient.Transport = h.apiCallTransport(auth)

	resp, errDo := httpClient.Do(req)
	if errDo != nil {
		log.WithError(errDo).Debug("management APICall request failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "request failed"})
		return
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
	}()

	respBody, errReadAll := io.ReadAll(resp.Body)
	if errReadAll != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to read response"})
		return
	}

	c.JSON(http.StatusOK, apiCallResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       string(respBody),
	})
}

// BatchAPICall executes multiple management API calls in one request.
// It can also be used for bulk auth liveness checks by setting update_status=true
// so each result is reflected back into the auth runtime status.
func (h *Handler) BatchAPICall(c *gin.Context) {
	var body batchAPICallRequest
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if len(body.Items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "items is required"})
		return
	}

	results := make([]batchAPICallResult, 0, len(body.Items))
	for _, item := range body.Items {
		result := h.executeBatchAPICallItem(c.Request.Context(), item)
		results = append(results, result)
	}

	status := http.StatusOK
	hasFailure := false
	hasSuccess := false
	for _, item := range results {
		if item.Status == "ok" {
			hasSuccess = true
			continue
		}
		hasFailure = true
	}
	if hasFailure && hasSuccess {
		status = http.StatusMultiStatus
	} else if hasFailure {
		status = http.StatusBadGateway
	}

	c.JSON(status, gin.H{"items": results})
}

// BatchCheckAuthFiles performs a bulk liveness probe for multiple auth entries.
func (h *Handler) BatchCheckAuthFiles(c *gin.Context) {
	var body batchAuthCheckRequest
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	targets := h.resolveBatchCheckTargets(body)
	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no auth targets provided"})
		return
	}

	results := make([]batchAPICallResult, 0, len(targets))
	for _, auth := range targets {
		results = append(results, h.checkSingleAuth(c.Request.Context(), auth, body.UpdateStatus))
	}

	status := http.StatusOK
	hasFailure := false
	hasSuccess := false
	for _, item := range results {
		if item.Status == "ok" {
			hasSuccess = true
			continue
		}
		hasFailure = true
	}
	if hasFailure && hasSuccess {
		status = http.StatusMultiStatus
	} else if hasFailure {
		status = http.StatusBadGateway
	}

	c.JSON(status, gin.H{"items": results})
}

func (h *Handler) executeBatchAPICallItem(ctx context.Context, item batchAPICallItem) batchAPICallResult {
	authIndex := firstNonEmptyString(item.AuthIndexSnake, item.AuthIndexCamel, item.AuthIndexPascal)
	result := batchAPICallResult{
		Name:      strings.TrimSpace(item.Name),
		AuthIndex: authIndex,
		Status:    "error",
	}

	if ctx == nil {
		ctx = context.Background()
	}

	method := strings.ToUpper(strings.TrimSpace(item.Method))
	if method == "" {
		result.Error = "missing method"
		return result
	}

	urlStr := strings.TrimSpace(item.URL)
	if urlStr == "" {
		result.Error = "missing url"
		return result
	}
	parsedURL, errParseURL := url.Parse(urlStr)
	if errParseURL != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		result.Error = "invalid url"
		return result
	}

	auth := h.authByIdentifier(authIndex, result.Name)
	if auth != nil {
		auth.EnsureIndex()
		result.Name = authDisplayName(auth)
		result.AuthIndex = auth.Index
	}

	reqHeaders := item.Header
	if reqHeaders == nil {
		reqHeaders = map[string]string{}
	}

	var hostOverride string
	var token string
	var tokenResolved bool
	var tokenErr error
	for key, value := range reqHeaders {
		if !strings.Contains(value, "$TOKEN$") {
			continue
		}
		if !tokenResolved {
			token, tokenErr = h.resolveTokenForAuth(ctx, auth)
			tokenResolved = true
		}
		if auth != nil && token == "" {
			if tokenErr != nil {
				result.Error = "auth token refresh failed"
				h.updateAuthProbeStatus(ctx, auth, result, item.UpdateStatus)
				return result
			}
			result.Error = "auth token not found"
			h.updateAuthProbeStatus(ctx, auth, result, item.UpdateStatus)
			return result
		}
		if token == "" {
			continue
		}
		reqHeaders[key] = strings.ReplaceAll(value, "$TOKEN$", token)
	}

	var requestBody io.Reader
	if item.Data != "" {
		requestBody = strings.NewReader(item.Data)
	}

	req, errNewRequest := http.NewRequestWithContext(ctx, method, urlStr, requestBody)
	if errNewRequest != nil {
		result.Error = "failed to build request"
		h.updateAuthProbeStatus(ctx, auth, result, item.UpdateStatus)
		return result
	}

	for key, value := range reqHeaders {
		if strings.EqualFold(key, "host") {
			hostOverride = strings.TrimSpace(value)
			continue
		}
		req.Header.Set(key, value)
	}
	if h != nil && h.authManager != nil && auth != nil {
		if errPrepare := h.authManager.PrepareHttpRequest(ctx, auth, req); errPrepare != nil {
			result.Error = fmt.Sprintf("failed to prepare request: %v", errPrepare)
			h.updateAuthProbeStatus(ctx, auth, result, item.UpdateStatus)
			return result
		}
	}
	if hostOverride != "" {
		req.Host = hostOverride
	}

	httpClient := &http.Client{
		Timeout: defaultAPICallTimeout,
	}
	httpClient.Transport = h.apiCallTransport(auth)

	resp, errDo := httpClient.Do(req)
	if errDo != nil {
		log.WithError(errDo).Debug("management batch APICall request failed")
		result.Error = "request failed"
		h.updateAuthProbeStatus(ctx, auth, result, item.UpdateStatus)
		return result
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
	}()

	respBody, errReadAll := io.ReadAll(resp.Body)
	if errReadAll != nil {
		result.Error = "failed to read response"
		h.updateAuthProbeStatus(ctx, auth, result, item.UpdateStatus)
		return result
	}

	result.StatusCode = resp.StatusCode
	result.Header = resp.Header
	result.Body = string(respBody)
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		result.Status = "ok"
	} else {
		result.Error = fmt.Sprintf("upstream returned status %d", resp.StatusCode)
	}
	h.updateAuthProbeStatus(ctx, auth, result, item.UpdateStatus)
	return result
}

func (h *Handler) authByIdentifier(authIndex, name string) *coreauth.Auth {
	if auth := h.authByIndex(authIndex); auth != nil {
		return auth
	}
	name = strings.TrimSpace(name)
	if name == "" || h == nil || h.authManager == nil {
		return nil
	}
	if auth, ok := h.authManager.GetByID(name); ok {
		return auth
	}
	for _, auth := range h.authManager.List() {
		if auth == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(auth.FileName), name) {
			return auth
		}
	}
	return nil
}

func authDisplayName(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}
	return strings.TrimSpace(auth.ID)
}

func (h *Handler) updateAuthProbeStatus(ctx context.Context, auth *coreauth.Auth, result batchAPICallResult, shouldUpdate bool) {
	if !shouldUpdate || h == nil || h.authManager == nil || auth == nil {
		return
	}
	updated := auth.Clone()
	if updated == nil {
		return
	}
	now := time.Now().UTC()
	updated.UpdatedAt = now
	updated.NextRetryAfter = time.Time{}
	if result.Status == "ok" {
		updated.Status = coreauth.StatusActive
		updated.StatusMessage = ""
		updated.Unavailable = false
		updated.LastError = nil
		updated.LastRefreshedAt = now
	} else {
		updated.Status = coreauth.StatusError
		updated.StatusMessage = strings.TrimSpace(result.Error)
		updated.Unavailable = true
	}
	_, _ = h.authManager.Update(ctx, updated)
}

func (h *Handler) resolveBatchCheckTargets(body batchAuthCheckRequest) []*coreauth.Auth {
	if h == nil || h.authManager == nil {
		return nil
	}
	if body.IncludeAll {
		return dedupeAuthTargets(h.authManager.List())
	}

	seen := make(map[string]struct{})
	targets := make([]*coreauth.Auth, 0, len(body.AuthIndexes)+len(body.Names))
	for _, authIndex := range body.AuthIndexes {
		if auth := h.authByIndex(authIndex); auth != nil {
			if _, ok := seen[auth.ID]; ok {
				continue
			}
			seen[auth.ID] = struct{}{}
			targets = append(targets, auth)
		}
	}
	for _, name := range body.Names {
		if auth := h.authByIdentifier("", name); auth != nil {
			if _, ok := seen[auth.ID]; ok {
				continue
			}
			seen[auth.ID] = struct{}{}
			targets = append(targets, auth)
		}
	}
	return targets
}

func dedupeAuthTargets(auths []*coreauth.Auth) []*coreauth.Auth {
	if len(auths) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(auths))
	result := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if auth == nil || strings.TrimSpace(auth.ID) == "" {
			continue
		}
		if _, ok := seen[auth.ID]; ok {
			continue
		}
		seen[auth.ID] = struct{}{}
		result = append(result, auth)
	}
	return result
}

func (h *Handler) checkSingleAuth(ctx context.Context, auth *coreauth.Auth, updateStatus bool) batchAPICallResult {
	if auth == nil {
		return batchAPICallResult{Status: "error", Error: "auth not found"}
	}
	auth.EnsureIndex()
	method, targetURL, headers, body, errProbe := buildAuthProbeRequest(auth)
	if errProbe != nil {
		result := batchAPICallResult{
			Name:      authDisplayName(auth),
			AuthIndex: auth.Index,
			Status:    "error",
			Error:     errProbe.Error(),
		}
		h.updateAuthProbeStatus(ctx, auth, result, updateStatus)
		return result
	}

	item := batchAPICallItem{
		Name:         authDisplayName(auth),
		AuthIndexSnake: &auth.Index,
		Method:       method,
		URL:          targetURL,
		Header:       headers,
		Data:         body,
		UpdateStatus: updateStatus,
	}
	return h.executeBatchAPICallItem(ctx, item)
}

func buildAuthProbeRequest(auth *coreauth.Auth) (string, string, map[string]string, string, error) {
	if auth == nil {
		return "", "", nil, "", fmt.Errorf("auth not found")
	}
	providerKey := strings.ToLower(strings.TrimSpace(auth.Provider))
	if auth.Attributes != nil {
		if compat := strings.TrimSpace(auth.Attributes["compat_name"]); compat != "" {
			baseURL := strings.TrimSpace(auth.Attributes["base_url"])
			if baseURL == "" {
				return "", "", nil, "", fmt.Errorf("missing base_url for openai compatible auth")
			}
			return http.MethodGet, strings.TrimRight(baseURL, "/") + "/models", map[string]string{}, "", nil
		}
	}

	switch providerKey {
	case "gemini":
		return http.MethodGet, "https://generativelanguage.googleapis.com/v1beta/models", map[string]string{}, "", nil
	case "gemini-cli":
		return http.MethodGet, "https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels", map[string]string{"Content-Type": "application/json"}, "{}", nil
	case "claude":
		return http.MethodGet, "https://api.anthropic.com/v1/models", map[string]string{"anthropic-version": "2023-06-01"}, "", nil
	case "codex":
		return http.MethodGet, "https://api.openai.com/v1/models", map[string]string{}, "", nil
	case "antigravity":
		return http.MethodGet, "https://api.openai.com/v1/models", map[string]string{}, "", nil
	case "kimi":
		return http.MethodGet, "https://api.moonshot.cn/v1/models", map[string]string{}, "", nil
	case "vertex":
		projectID := strings.TrimSpace(authAttribute(auth, "project_id"))
		if projectID == "" && auth.Metadata != nil {
			if v, ok := auth.Metadata["project_id"].(string); ok {
				projectID = strings.TrimSpace(v)
			}
		}
		if projectID == "" {
			return "", "", nil, "", fmt.Errorf("missing project_id for vertex auth")
		}
		return http.MethodGet, fmt.Sprintf("https://us-central1-aiplatform.googleapis.com/v1/projects/%s/locations/us-central1/publishers/google/models", projectID), map[string]string{}, "", nil
	default:
		if baseURL := strings.TrimSpace(authAttribute(auth, "base_url")); baseURL != "" {
			return http.MethodGet, strings.TrimRight(baseURL, "/") + "/models", map[string]string{}, "", nil
		}
	}
	return "", "", nil, "", fmt.Errorf("unsupported auth provider: %s", providerKey)
}

func (h *Handler) collectAuthProbeTargets() []batchAPICallResult {
	if h == nil || h.authManager == nil {
		return nil
	}
	auths := h.authManager.List()
	results := make([]batchAPICallResult, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		auth.EnsureIndex()
		results = append(results, batchAPICallResult{
			Name:      authDisplayName(auth),
			AuthIndex: auth.Index,
			Status:    string(auth.Status),
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Name == results[j].Name {
			return results[i].AuthIndex < results[j].AuthIndex
		}
		return strings.ToLower(results[i].Name) < strings.ToLower(results[j].Name)
	})
	return results
}

func firstNonEmptyString(values ...*string) string {
	for _, v := range values {
		if v == nil {
			continue
		}
		if out := strings.TrimSpace(*v); out != "" {
			return out
		}
	}
	return ""
}

func tokenValueForAuth(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if v := tokenValueFromMetadata(auth.Metadata); v != "" {
		return v
	}
	if auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["api_key"]); v != "" {
			return v
		}
	}
	if shared := geminicli.ResolveSharedCredential(auth.Runtime); shared != nil {
		if v := tokenValueFromMetadata(shared.MetadataSnapshot()); v != "" {
			return v
		}
	}
	return ""
}

func (h *Handler) resolveTokenForAuth(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if auth == nil {
		return "", nil
	}

	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if provider == "gemini-cli" {
		token, errToken := h.refreshGeminiOAuthAccessToken(ctx, auth)
		return token, errToken
	}
	if provider == "antigravity" {
		token, errToken := h.refreshAntigravityOAuthAccessToken(ctx, auth)
		return token, errToken
	}

	return tokenValueForAuth(auth), nil
}

func (h *Handler) refreshGeminiOAuthAccessToken(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if auth == nil {
		return "", nil
	}

	metadata, updater := geminiOAuthMetadata(auth)
	if len(metadata) == 0 {
		return "", fmt.Errorf("gemini oauth metadata missing")
	}

	base := make(map[string]any)
	if tokenRaw, ok := metadata["token"].(map[string]any); ok && tokenRaw != nil {
		base = cloneMap(tokenRaw)
	}

	var token oauth2.Token
	if len(base) > 0 {
		if raw, errMarshal := json.Marshal(base); errMarshal == nil {
			_ = json.Unmarshal(raw, &token)
		}
	}

	if token.AccessToken == "" {
		token.AccessToken = stringValue(metadata, "access_token")
	}
	if token.RefreshToken == "" {
		token.RefreshToken = stringValue(metadata, "refresh_token")
	}
	if token.TokenType == "" {
		token.TokenType = stringValue(metadata, "token_type")
	}
	if token.Expiry.IsZero() {
		if expiry := stringValue(metadata, "expiry"); expiry != "" {
			if ts, errParseTime := time.Parse(time.RFC3339, expiry); errParseTime == nil {
				token.Expiry = ts
			}
		}
	}

	conf := &oauth2.Config{
		ClientID:     geminiOAuthClientID,
		ClientSecret: geminiOAuthClientSecret,
		Scopes:       geminiOAuthScopes,
		Endpoint:     google.Endpoint,
	}

	ctxToken := ctx
	httpClient := &http.Client{
		Timeout:   defaultAPICallTimeout,
		Transport: h.apiCallTransport(auth),
	}
	ctxToken = context.WithValue(ctxToken, oauth2.HTTPClient, httpClient)

	src := conf.TokenSource(ctxToken, &token)
	currentToken, errToken := src.Token()
	if errToken != nil {
		return "", errToken
	}

	merged := buildOAuthTokenMap(base, currentToken)
	fields := buildOAuthTokenFields(currentToken, merged)
	if updater != nil {
		updater(fields)
	}
	return strings.TrimSpace(currentToken.AccessToken), nil
}

func (h *Handler) refreshAntigravityOAuthAccessToken(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if auth == nil {
		return "", nil
	}

	metadata := auth.Metadata
	if len(metadata) == 0 {
		return "", fmt.Errorf("antigravity oauth metadata missing")
	}

	current := strings.TrimSpace(tokenValueFromMetadata(metadata))
	if current != "" && !antigravityTokenNeedsRefresh(metadata) {
		return current, nil
	}

	refreshToken := stringValue(metadata, "refresh_token")
	if refreshToken == "" {
		return "", fmt.Errorf("antigravity refresh token missing")
	}

	tokenURL := strings.TrimSpace(antigravityOAuthTokenURL)
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	form := url.Values{}
	form.Set("client_id", antigravityOAuthClientID)
	form.Set("client_secret", antigravityOAuthClientSecret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if errReq != nil {
		return "", errReq
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{
		Timeout:   defaultAPICallTimeout,
		Transport: h.apiCallTransport(auth),
	}
	resp, errDo := httpClient.Do(req)
	if errDo != nil {
		return "", errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
	}()

	bodyBytes, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return "", errRead
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("antigravity oauth token refresh failed: status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if errUnmarshal := json.Unmarshal(bodyBytes, &tokenResp); errUnmarshal != nil {
		return "", errUnmarshal
	}

	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return "", fmt.Errorf("antigravity oauth token refresh returned empty access_token")
	}

	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	now := time.Now()
	auth.Metadata["access_token"] = strings.TrimSpace(tokenResp.AccessToken)
	if strings.TrimSpace(tokenResp.RefreshToken) != "" {
		auth.Metadata["refresh_token"] = strings.TrimSpace(tokenResp.RefreshToken)
	}
	if tokenResp.ExpiresIn > 0 {
		auth.Metadata["expires_in"] = tokenResp.ExpiresIn
		auth.Metadata["timestamp"] = now.UnixMilli()
		auth.Metadata["expired"] = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339)
	}
	auth.Metadata["type"] = "antigravity"

	if h != nil && h.authManager != nil {
		auth.LastRefreshedAt = now
		auth.UpdatedAt = now
		_, _ = h.authManager.Update(ctx, auth)
	}

	return strings.TrimSpace(tokenResp.AccessToken), nil
}

func antigravityTokenNeedsRefresh(metadata map[string]any) bool {
	// Refresh a bit early to avoid requests racing token expiry.
	const skew = 30 * time.Second

	if metadata == nil {
		return true
	}
	if expStr, ok := metadata["expired"].(string); ok {
		if ts, errParse := time.Parse(time.RFC3339, strings.TrimSpace(expStr)); errParse == nil {
			return !ts.After(time.Now().Add(skew))
		}
	}
	expiresIn := int64Value(metadata["expires_in"])
	timestampMs := int64Value(metadata["timestamp"])
	if expiresIn > 0 && timestampMs > 0 {
		exp := time.UnixMilli(timestampMs).Add(time.Duration(expiresIn) * time.Second)
		return !exp.After(time.Now().Add(skew))
	}
	return true
}

func int64Value(raw any) int64 {
	switch typed := raw.(type) {
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case uint:
		return int64(typed)
	case uint32:
		return int64(typed)
	case uint64:
		if typed > uint64(^uint64(0)>>1) {
			return 0
		}
		return int64(typed)
	case float32:
		return int64(typed)
	case float64:
		return int64(typed)
	case json.Number:
		if i, errParse := typed.Int64(); errParse == nil {
			return i
		}
	case string:
		if s := strings.TrimSpace(typed); s != "" {
			if i, errParse := json.Number(s).Int64(); errParse == nil {
				return i
			}
		}
	}
	return 0
}

func geminiOAuthMetadata(auth *coreauth.Auth) (map[string]any, func(map[string]any)) {
	if auth == nil {
		return nil, nil
	}
	if shared := geminicli.ResolveSharedCredential(auth.Runtime); shared != nil {
		snapshot := shared.MetadataSnapshot()
		return snapshot, func(fields map[string]any) { shared.MergeMetadata(fields) }
	}
	return auth.Metadata, func(fields map[string]any) {
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		for k, v := range fields {
			auth.Metadata[k] = v
		}
	}
}

func stringValue(metadata map[string]any, key string) string {
	if len(metadata) == 0 || key == "" {
		return ""
	}
	if v, ok := metadata[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func buildOAuthTokenMap(base map[string]any, tok *oauth2.Token) map[string]any {
	merged := cloneMap(base)
	if merged == nil {
		merged = make(map[string]any)
	}
	if tok == nil {
		return merged
	}
	if raw, errMarshal := json.Marshal(tok); errMarshal == nil {
		var tokenMap map[string]any
		if errUnmarshal := json.Unmarshal(raw, &tokenMap); errUnmarshal == nil {
			for k, v := range tokenMap {
				merged[k] = v
			}
		}
	}
	return merged
}

func buildOAuthTokenFields(tok *oauth2.Token, merged map[string]any) map[string]any {
	fields := make(map[string]any, 5)
	if tok != nil && tok.AccessToken != "" {
		fields["access_token"] = tok.AccessToken
	}
	if tok != nil && tok.TokenType != "" {
		fields["token_type"] = tok.TokenType
	}
	if tok != nil && tok.RefreshToken != "" {
		fields["refresh_token"] = tok.RefreshToken
	}
	if tok != nil && !tok.Expiry.IsZero() {
		fields["expiry"] = tok.Expiry.Format(time.RFC3339)
	}
	if len(merged) > 0 {
		fields["token"] = cloneMap(merged)
	}
	return fields
}

func tokenValueFromMetadata(metadata map[string]any) string {
	if len(metadata) == 0 {
		return ""
	}
	if v, ok := metadata["accessToken"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v, ok := metadata["access_token"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if tokenRaw, ok := metadata["token"]; ok && tokenRaw != nil {
		switch typed := tokenRaw.(type) {
		case string:
			if v := strings.TrimSpace(typed); v != "" {
				return v
			}
		case map[string]any:
			if v, ok := typed["access_token"].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
			if v, ok := typed["accessToken"].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		case map[string]string:
			if v := strings.TrimSpace(typed["access_token"]); v != "" {
				return v
			}
			if v := strings.TrimSpace(typed["accessToken"]); v != "" {
				return v
			}
		}
	}
	if v, ok := metadata["token"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v, ok := metadata["id_token"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v, ok := metadata["cookie"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return ""
}

func (h *Handler) authByIndex(authIndex string) *coreauth.Auth {
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" || h == nil || h.authManager == nil {
		return nil
	}
	auths := h.authManager.List()
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		auth.EnsureIndex()
		if auth.Index == authIndex {
			return auth
		}
	}
	return nil
}

func (h *Handler) apiCallTransport(auth *coreauth.Auth) http.RoundTripper {
	var proxyCandidates []string
	if auth != nil {
		if proxyStr := strings.TrimSpace(auth.ProxyURL); proxyStr != "" {
			proxyCandidates = append(proxyCandidates, proxyStr)
		}
		if h != nil && h.cfg != nil {
			if proxyStr := strings.TrimSpace(proxyURLFromAPIKeyConfig(h.cfg, auth)); proxyStr != "" {
				proxyCandidates = append(proxyCandidates, proxyStr)
			}
		}
	}
	if h != nil && h.cfg != nil {
		if proxyStr := strings.TrimSpace(h.cfg.ProxyURL); proxyStr != "" {
			proxyCandidates = append(proxyCandidates, proxyStr)
		}
	}

	for _, proxyStr := range proxyCandidates {
		if transport := buildProxyTransport(proxyStr); transport != nil {
			return transport
		}
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || transport == nil {
		return &http.Transport{Proxy: nil}
	}
	clone := transport.Clone()
	clone.Proxy = nil
	return clone
}

type apiKeyConfigEntry interface {
	GetAPIKey() string
	GetBaseURL() string
}

func resolveAPIKeyConfig[T apiKeyConfigEntry](entries []T, auth *coreauth.Auth) *T {
	if auth == nil || len(entries) == 0 {
		return nil
	}
	attrKey, attrBase := "", ""
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range entries {
		entry := &entries[i]
		cfgKey := strings.TrimSpace((*entry).GetAPIKey())
		cfgBase := strings.TrimSpace((*entry).GetBaseURL())
		if attrKey != "" && attrBase != "" {
			if strings.EqualFold(cfgKey, attrKey) && strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	if attrKey != "" {
		for i := range entries {
			entry := &entries[i]
			if strings.EqualFold(strings.TrimSpace((*entry).GetAPIKey()), attrKey) {
				return entry
			}
		}
	}
	return nil
}

func proxyURLFromAPIKeyConfig(cfg *config.Config, auth *coreauth.Auth) string {
	if cfg == nil || auth == nil {
		return ""
	}
	authKind, authAccount := auth.AccountInfo()
	if !strings.EqualFold(strings.TrimSpace(authKind), "api_key") {
		return ""
	}

	attrs := auth.Attributes
	compatName := ""
	providerKey := ""
	if len(attrs) > 0 {
		compatName = strings.TrimSpace(attrs["compat_name"])
		providerKey = strings.TrimSpace(attrs["provider_key"])
	}
	if compatName != "" || strings.EqualFold(strings.TrimSpace(auth.Provider), "openai-compatibility") {
		return resolveOpenAICompatAPIKeyProxyURL(cfg, auth, strings.TrimSpace(authAccount), providerKey, compatName)
	}

	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "gemini":
		if entry := resolveAPIKeyConfig(cfg.GeminiKey, auth); entry != nil {
			return strings.TrimSpace(entry.ProxyURL)
		}
	case "claude":
		if entry := resolveAPIKeyConfig(cfg.ClaudeKey, auth); entry != nil {
			return strings.TrimSpace(entry.ProxyURL)
		}
	case "codex":
		if entry := resolveAPIKeyConfig(cfg.CodexKey, auth); entry != nil {
			return strings.TrimSpace(entry.ProxyURL)
		}
	}
	return ""
}

func resolveOpenAICompatAPIKeyProxyURL(cfg *config.Config, auth *coreauth.Auth, apiKey, providerKey, compatName string) string {
	if cfg == nil || auth == nil {
		return ""
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return ""
	}
	candidates := make([]string, 0, 3)
	if v := strings.TrimSpace(compatName); v != "" {
		candidates = append(candidates, v)
	}
	if v := strings.TrimSpace(providerKey); v != "" {
		candidates = append(candidates, v)
	}
	if v := strings.TrimSpace(auth.Provider); v != "" {
		candidates = append(candidates, v)
	}

	for i := range cfg.OpenAICompatibility {
		compat := &cfg.OpenAICompatibility[i]
		for _, candidate := range candidates {
			if candidate != "" && strings.EqualFold(strings.TrimSpace(candidate), compat.Name) {
				for j := range compat.APIKeyEntries {
					entry := &compat.APIKeyEntries[j]
					if strings.EqualFold(strings.TrimSpace(entry.APIKey), apiKey) {
						return strings.TrimSpace(entry.ProxyURL)
					}
				}
				return ""
			}
		}
	}
	return ""
}

func buildProxyTransport(proxyStr string) *http.Transport {
	transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyStr)
	if errBuild != nil {
		log.WithError(errBuild).Debug("build proxy transport failed")
		return nil
	}
	return transport
}
