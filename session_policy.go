// SPDX-License-Identifier: MIT
// Copyright (C) 2026 eaopen contributors

package oidcauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	common "github.com/mickael-kerjean/filestash/server/common"
	"github.com/mickael-kerjean/filestash/server/pkg/session"
	"github.com/mickael-kerjean/filestash/server/pkg/token"
)

const maxOIDCSessionAge = 15 * time.Minute

// Filestash plugin routes can omit PluginInjector, so enforce token age on the
// parent router before any core or plugin route handles the request.
func registerOIDCSessionGuard(router *mux.Router) error {
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			if common.Config.Get("middleware.identity_provider.type").String() != pluginID ||
				req.URL.Path == common.WithBase("/api/session/auth/") {
				next.ServeHTTP(res, req)
				return
			}

			authorization := token.From(req)
			// WOPI converts access_token to authorization only inside its route.
			if authorization == "" && strings.HasPrefix(req.URL.Path, common.WithBase("/api/wopi/files/")) {
				authorization = req.URL.Query().Get("access_token")
			}
			if authorization != "" {
				app := &common.App{Authorization: authorization}
				userSession, err := session.FromRequest(req, app)
				if err != nil || !oidcSessionCurrent(userSession["timestamp"], time.Now()) {
					common.SendErrorResult(res, common.ErrNotAuthorized)
					return
				}
			}
			next.ServeHTTP(res, req)
		})
	})
	return nil
}

// enforceOIDCSessionAge bounds the lifetime of Filestash's encrypted, otherwise
// long-lived session token. The IdP admission policy is rechecked on the next
// OIDC login, after this token expires.
func enforceOIDCSessionAge(next common.HandlerFunc) common.HandlerFunc {
	return func(app *common.App, res http.ResponseWriter, req *http.Request) {
		if common.Config.Get("middleware.identity_provider.type").String() != pluginID {
			next(app, res, req)
			return
		}

		// Filestash's direct storage login would bypass the OIDC admission policy.
		if req.Method == http.MethodPost && req.URL.Path == common.WithBase("/api/session") {
			common.SendErrorResult(res, common.ErrNotAllowed)
			return
		}

		if app != nil && len(app.Session) > 0 && app.Share.Id == "" {
			if !oidcSessionCurrent(app.Session["timestamp"], time.Now()) {
				common.SendErrorResult(res, common.ErrNotAuthorized)
				return
			}
		}

		next(app, res, req)
	}
}

func oidcSessionCurrent(rawTimestamp string, now time.Time) bool {
	issuedAt, err := time.Parse(time.RFC3339, rawTimestamp)
	if err != nil || issuedAt.After(now) {
		return false
	}
	return now.Sub(issuedAt) < maxOIDCSessionAge
}
