// Package oidc implements a minimal OpenID Connect authorization-code login
// against an operator-configured identity provider, using only the standard
// library. It performs discovery, exchanges the code for an access token, and
// reads the userinfo endpoint (which avoids local JWT signature verification).
//
// Nothing here points at a vendor: the issuer, client id/secret and redirect
// URL all come from the operator's own IdP configuration.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"vdxclone/internal/config"
)

type Provider struct {
	cfg  config.OIDCConfig
	mu   sync.Mutex
	disc *discovery
}

type discovery struct {
	AuthEndpoint     string `json:"authorization_endpoint"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserinfoEndpoint string `json:"userinfo_endpoint"`
	fetchedAt        time.Time
}

// UserInfo is the identity we map onto a local user.
type UserInfo struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Username string `json:"preferred_username"`
}

func New(cfg config.OIDCConfig) *Provider { return &Provider{cfg: cfg} }

func (p *Provider) Enabled() bool {
	return p.cfg.Enabled && p.cfg.Issuer != "" && p.cfg.ClientID != "" && p.cfg.RedirectURL != ""
}

// discover fetches and caches the IdP's well-known configuration.
func (p *Provider) discover(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disc != nil && time.Since(p.disc.fetchedAt) < time.Hour {
		return p.disc, nil
	}
	u := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: HTTP %d", resp.StatusCode)
	}
	var d discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	d.fetchedAt = time.Now()
	p.disc = &d
	return &d, nil
}

// AuthURL builds the IdP authorization URL for the given CSRF state.
func (p *Provider) AuthURL(ctx context.Context, state string) (string, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	return d.AuthEndpoint + "?" + q.Encode(), nil
}

// Exchange swaps an authorization code for an access token.
func (p *Provider) Exchange(ctx context.Context, code string) (string, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc token exchange: HTTP %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("oidc: no access token returned")
	}
	return tok.AccessToken, nil
}

// UserInfo reads the identity associated with an access token.
func (p *Provider) UserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return UserInfo{}, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.UserinfoEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return UserInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return UserInfo{}, fmt.Errorf("oidc userinfo: HTTP %d", resp.StatusCode)
	}
	var ui UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&ui); err != nil {
		return UserInfo{}, err
	}
	if ui.Subject == "" {
		return UserInfo{}, fmt.Errorf("oidc userinfo: missing sub")
	}
	if ui.Username == "" {
		if ui.Email != "" {
			ui.Username = ui.Email
		} else {
			ui.Username = "oidc-" + ui.Subject
		}
	}
	return ui, nil
}
