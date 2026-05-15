package coreauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const thirdPartyStateTokenTTL = 10 * time.Minute

type ThirdPartyState struct {
	Provider   string `json:"provider"`
	Nonce      string `json:"nonce"`
	RedirectTo string `json:"redirect_to,omitempty"`
	// AuthRequestID carries the OIDC OP auth_request UUID across the
	// third-party login round-trip. The OP issues a LoginURL with this
	// ID when it needs the user to authenticate; after the third-party
	// callback completes, the caller uses it to mark the auth_request
	// as Done and redirect the user back into the OP's
	// /authorize/callback?id=<auth_request_id> path so the OIDC flow
	// resumes with an authorization code for the original client.
	// Empty when the third-party login was initiated outside an OIDC
	// flow (e.g. console direct login).
	AuthRequestID string    `json:"auth_request_id,omitempty"`
	IssuedAt      time.Time `json:"issued_at"`
}

type OAuthDiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type OAuthResolvedProvider struct {
	Name             string
	Type             string
	AuthorizeURL     string
	TokenURL         string
	UserInfoURL      string
	ClientID         string
	ClientSecret     string
	Scopes           []string
	AutoLinkByEmail  bool
	SubjectField     string
	LoginField       string
	EmailField       string
	DisplayNameField string
	AvatarURLField   string
	ProfileURLField  string
}

type OAuthProfile struct {
	Subject     string
	Login       string
	Email       string
	DisplayName string
	ProfileURL  string
	AvatarURL   string
	Claims      map[string]any
}

func NewThirdPartyState(provider, redirectTo, authRequestID string) (ThirdPartyState, error) {
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return ThirdPartyState{}, fmt.Errorf("generate third-party state nonce: %w", err)
	}
	return ThirdPartyState{
		Provider:      strings.ToLower(strings.TrimSpace(provider)),
		Nonce:         base64.RawURLEncoding.EncodeToString(nonceBytes),
		RedirectTo:    strings.TrimSpace(redirectTo),
		AuthRequestID: strings.TrimSpace(authRequestID),
		IssuedAt:      time.Now().UTC(),
	}, nil
}

func SignThirdPartyState(secret string, state ThirdPartyState) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("third-party state secret is required")
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("marshal third-party state: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payloadEncoded))
	signatureEncoded := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payloadEncoded + "." + signatureEncoded, nil
}

func VerifyThirdPartyState(secret, token string) (ThirdPartyState, error) {
	if strings.TrimSpace(secret) == "" {
		return ThirdPartyState{}, fmt.Errorf("third-party state secret is required")
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 {
		return ThirdPartyState{}, fmt.Errorf("invalid third-party state token")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0]))
	expectedSignature := mac.Sum(nil)
	actualSignature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ThirdPartyState{}, fmt.Errorf("decode third-party state signature: %w", err)
	}
	if !hmac.Equal(actualSignature, expectedSignature) {
		return ThirdPartyState{}, fmt.Errorf("invalid third-party state signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ThirdPartyState{}, fmt.Errorf("decode third-party state payload: %w", err)
	}

	var state ThirdPartyState
	if err := json.Unmarshal(payload, &state); err != nil {
		return ThirdPartyState{}, fmt.Errorf("unmarshal third-party state payload: %w", err)
	}
	if state.IssuedAt.IsZero() || time.Since(state.IssuedAt.UTC()) > thirdPartyStateTokenTTL {
		return ThirdPartyState{}, fmt.Errorf("third-party state token expired")
	}
	return state, nil
}

func ExchangeAuthorizationCode(
	ctx context.Context,
	client *http.Client,
	provider OAuthResolvedProvider,
	code string,
	redirectURI string,
) (string, map[string]any, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Set("redirect_uri", strings.TrimSpace(redirectURI))
	form.Set("client_id", provider.ClientID)
	form.Set("client_secret", provider.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, fmt.Errorf("build token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("read token exchange response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("exchange authorization code: upstream returned %s", resp.Status)
	}

	payload, err := decodeOAuthObject(body)
	if err != nil {
		return "", nil, err
	}
	token := lookupOAuthString(payload, "access_token")
	if token == "" {
		return "", nil, fmt.Errorf("exchange authorization code: access_token is required")
	}
	return token, payload, nil
}

func FetchOAuthProfile(ctx context.Context, client *http.Client, provider OAuthResolvedProvider, accessToken string) (OAuthProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.UserInfoURL, nil)
	if err != nil {
		return OAuthProfile{}, fmt.Errorf("build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return OAuthProfile{}, fmt.Errorf("fetch userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return OAuthProfile{}, fmt.Errorf("read userinfo response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return OAuthProfile{}, fmt.Errorf("fetch userinfo: upstream returned %s", resp.Status)
	}

	claims, err := decodeOAuthObject(body)
	if err != nil {
		return OAuthProfile{}, err
	}
	profile := OAuthProfile{
		Subject:     lookupOAuthString(claims, provider.SubjectField),
		Login:       lookupOAuthString(claims, provider.LoginField),
		Email:       lookupOAuthString(claims, provider.EmailField),
		DisplayName: lookupOAuthString(claims, provider.DisplayNameField),
		ProfileURL:  lookupOAuthString(claims, provider.ProfileURLField),
		AvatarURL:   lookupOAuthString(claims, provider.AvatarURLField),
		Claims:      claims,
	}
	if profile.Subject == "" {
		return OAuthProfile{}, fmt.Errorf("userinfo response does not include subject field %q", provider.SubjectField)
	}
	return profile, nil
}

func ResolveOIDCDiscovery(ctx context.Context, client *http.Client, issuerURL string) (OAuthDiscoveryDocument, error) {
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuerURL == "" {
		return OAuthDiscoveryDocument{}, fmt.Errorf("oidc issuer_url is required")
	}
	discoveryURL := issuerURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return OAuthDiscoveryDocument{}, fmt.Errorf("build oidc discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return OAuthDiscoveryDocument{}, fmt.Errorf("resolve oidc discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return OAuthDiscoveryDocument{}, fmt.Errorf("read oidc discovery response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return OAuthDiscoveryDocument{}, fmt.Errorf("resolve oidc discovery: upstream returned %s", resp.Status)
	}

	var document OAuthDiscoveryDocument
	if err := json.Unmarshal(body, &document); err != nil {
		return OAuthDiscoveryDocument{}, fmt.Errorf("decode oidc discovery response: %w", err)
	}
	if strings.TrimSpace(document.AuthorizationEndpoint) == "" ||
		strings.TrimSpace(document.TokenEndpoint) == "" ||
		strings.TrimSpace(document.UserInfoEndpoint) == "" {
		return OAuthDiscoveryDocument{}, fmt.Errorf("oidc discovery response is missing required endpoints")
	}
	return document, nil
}

func decodeOAuthObject(body []byte) (map[string]any, error) {
	payload := map[string]any{}
	if err := json.Unmarshal(body, &payload); err == nil {
		return payload, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("decode oauth response: %w", err)
	}
	output := make(map[string]any, len(values))
	for key, value := range values {
		if len(value) == 1 {
			output[key] = value[0]
			continue
		}
		items := make([]any, 0, len(value))
		for _, item := range value {
			items = append(items, item)
		}
		output[key] = items
	}
	return output, nil
}

func lookupOAuthString(input map[string]any, field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}
	current := any(input)
	for _, segment := range strings.Split(field, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = object[segment]
		if !ok {
			return ""
		}
	}
	switch value := current.(type) {
	case string:
		return strings.TrimSpace(value)
	case json.Number:
		return value.String()
	case float64:
		if value == float64(int64(value)) {
			return strconv.FormatInt(int64(value), 10)
		}
		return strconv.FormatFloat(value, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(value), 'f', -1, 32)
	case int:
		return strconv.Itoa(value)
	case int64:
		return strconv.FormatInt(value, 10)
	case int32:
		return strconv.FormatInt(int64(value), 10)
	case uint:
		return strconv.FormatUint(uint64(value), 10)
	case uint64:
		return strconv.FormatUint(value, 10)
	case bool:
		return strconv.FormatBool(value)
	default:
		return ""
	}
}
