// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 eaopen contributors

package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	common "github.com/mickael-kerjean/filestash/server/common"
	"golang.org/x/oauth2"
)

const (
	pluginID          = "oidc"
	requestTimeout    = 15 * time.Second
	defaultScopes     = "openid profile email"
	defaultUserClaim  = "preferred_username"
	defaultGroupClaim = "groups"
)

var (
	pendingLogins = newStateStore(10*time.Minute, 4096)
	providerCache sync.Map // map[string]*oidc.Provider
)

func init() {
	common.Hooks.Register.AuthenticationMiddleware(pluginID, Plugin{})
}

// Plugin implements Filestash's IAuthentication middleware using standard
// OpenID Connect Authorization Code Flow with PKCE (S256).
type Plugin struct{}

func (Plugin) Setup() common.Form {
	return common.Form{Elmnts: []common.FormElement{
		{Name: "type", Type: "hidden", Value: pluginID},
		{
			Name:        "issuer",
			Type:        "text",
			Placeholder: "https://auth.example.com/application/o/filestash/",
			Description: "OIDC issuer URL. Use the exact issuer value, not the /.well-known/openid-configuration URL.",
			Required:    true,
		},
		{
			Name:        "client_id",
			Type:        "text",
			Placeholder: "Filestash OIDC client ID",
			Required:    true,
		},
		{
			Name:        "client_secret",
			Type:        "password",
			Placeholder: "Filestash OIDC client secret",
			Required:    true,
		},
		{
			Name:        "redirect_uri",
			Type:        "text",
			Placeholder: "https://files.example.com/api/session/auth/",
			Description: "Exact redirect URI registered at the identity provider.",
			Required:    true,
		},
		{
			Name:        "scopes",
			Type:        "text",
			Value:       defaultScopes,
			Placeholder: defaultScopes,
			Description: "Space- or comma-separated scopes. The openid scope is always added.",
		},
		{
			Name:        "username_claim",
			Type:        "text",
			Value:       defaultUserClaim,
			Placeholder: defaultUserClaim,
			Description: "Claim exposed as both .user and .username. Falls back to sub when absent.",
		},
		{
			Name:        "groups_claim",
			Type:        "text",
			Value:       defaultGroupClaim,
			Placeholder: defaultGroupClaim,
			Description: "Claim exposed as .groups (comma-separated) and .groups_json.",
		},
		{
			Name:        "userinfo",
			Type:        "select",
			Value:       "false",
			Opts:        []string{"false", "true"},
			Description: "Optionally merge claims from the OIDC UserInfo endpoint after validating the ID token.",
		},
	}}
}

func (Plugin) EntryPoint(idpParams map[string]string, req *http.Request, res http.ResponseWriter) error {
	cfg, err := parseConfig(idpParams)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(req.Context(), requestTimeout)
	defer cancel()

	provider, err := discoverProvider(ctx, cfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc discovery failed: %w", err)
	}

	state, err := randomToken(32)
	if err != nil {
		return fmt.Errorf("generate state: %w", err)
	}
	nonce, err := randomToken(32)
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	verifier := oauth2.GenerateVerifier()

	if err := pendingLogins.put(state, pendingLogin{
		CreatedAt:    time.Now(),
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		RedirectURI:  cfg.RedirectURI,
		Nonce:        nonce,
		CodeVerifier: verifier,
	}); err != nil {
		return err
	}

	oauthCfg := cfg.oauthConfig(provider)
	authURL := oauthCfg.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	http.Redirect(res, req, authURL, http.StatusSeeOther)
	return nil
}

func (Plugin) Callback(formData map[string]string, idpParams map[string]string, res http.ResponseWriter) (map[string]string, error) {
	if providerErr := strings.TrimSpace(formData["error"]); providerErr != "" {
		if providerErr == "access_denied" {
			return nil, common.ErrAuthenticationFailed
		}
		detail := strings.TrimSpace(formData["error_description"])
		if detail == "" {
			detail = providerErr
		}
		return nil, fmt.Errorf("oidc provider returned an error: %s", detail)
	}

	cfg, err := parseConfig(idpParams)
	if err != nil {
		return nil, err
	}

	state := strings.TrimSpace(formData["state"])
	code := strings.TrimSpace(formData["code"])
	if state == "" || code == "" {
		return nil, errors.New("oidc callback is missing state or code")
	}

	login, ok := pendingLogins.consume(state)
	if !ok {
		return nil, errors.New("oidc state is invalid, expired, or already used")
	}
	if login.Issuer != cfg.Issuer || login.ClientID != cfg.ClientID || login.RedirectURI != cfg.RedirectURI {
		return nil, errors.New("oidc configuration changed during authentication")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	provider, err := discoverProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	oauthCfg := cfg.oauthConfig(provider)
	token, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(login.CodeVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc code exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("oidc token response did not include an id_token")
	}

	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc id_token verification failed: %w", err)
	}
	if idToken.Nonce != login.Nonce {
		return nil, errors.New("oidc nonce validation failed")
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode oidc id_token claims: %w", err)
	}

	if cfg.UseUserInfo {
		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, fmt.Errorf("oidc userinfo request failed: %w", err)
		}
		if userInfo.Subject != idToken.Subject {
			return nil, errors.New("oidc userinfo subject does not match id_token subject")
		}
		userInfoClaims := map[string]any{}
		if err := userInfo.Claims(&userInfoClaims); err != nil {
			return nil, fmt.Errorf("decode oidc userinfo claims: %w", err)
		}
		claims = mergeClaims(claims, userInfoClaims)
	}

	// The verified ID token subject is authoritative even if another source
	// supplied a claim with the same name.
	claims["sub"] = idToken.Subject
	return exposeClaims(claims, cfg.UsernameClaim, cfg.GroupsClaim), nil
}

type pluginConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	Scopes        []string
	UsernameClaim string
	GroupsClaim   string
	UseUserInfo   bool
}

func parseConfig(params map[string]string) (pluginConfig, error) {
	cfg := pluginConfig{
		Issuer:        strings.TrimSpace(params["issuer"]),
		ClientID:      strings.TrimSpace(params["client_id"]),
		ClientSecret:  strings.TrimSpace(params["client_secret"]),
		RedirectURI:   strings.TrimSpace(params["redirect_uri"]),
		Scopes:        normalizeScopes(params["scopes"]),
		UsernameClaim: strings.TrimSpace(params["username_claim"]),
		GroupsClaim:   strings.TrimSpace(params["groups_claim"]),
		UseUserInfo:   parseBool(params["userinfo"]),
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = defaultUserClaim
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = defaultGroupClaim
	}

	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURI == "" {
		return pluginConfig{}, errors.New("oidc issuer, client_id, client_secret, and redirect_uri are required")
	}
	if err := validateRedirectURI(cfg.RedirectURI); err != nil {
		return pluginConfig{}, err
	}
	return cfg, nil
}

func (c pluginConfig) oauthConfig(provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.RedirectURI,
		Scopes:       c.Scopes,
	}
}

func discoverProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	if cached, ok := providerCache.Load(issuer); ok {
		return cached.(*oidc.Provider), nil
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	actual, _ := providerCache.LoadOrStore(issuer, provider)
	return actual.(*oidc.Provider), nil
}

func normalizeScopes(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		raw = defaultScopes
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	seen := map[string]bool{"openid": true}
	out := []string{"openid"}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	return out
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("oidc redirect_uri must be an absolute URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return nil
	}
	return errors.New("oidc redirect_uri must use HTTPS except for localhost development")
}
