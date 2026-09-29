// SPDX-License-Identifier: MIT
// Copyright (C) 2026 eaopen contributors

package oidcauth

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func mergeClaims(base, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func exposeClaims(claims map[string]any, usernameClaim, groupsClaim string) map[string]string {
	out := make(map[string]string, len(claims)+8)
	for key, value := range claims {
		if flattened, ok := flattenClaim(value); ok {
			out[key] = flattened
		}
	}

	sub := claimString(claims["sub"])
	username := claimString(claims[usernameClaim])
	if username == "" {
		username = sub
	}

	groups := claimStrings(claims[groupsClaim])
	groupsJSON, _ := json.Marshal(groups)
	rawClaims, _ := json.Marshal(claims)

	out["sub"] = sub
	out["user"] = username
	out["username"] = username
	out["groups"] = strings.Join(groups, ",")
	out["groups_json"] = string(groupsJSON)
	out["raw_claims"] = string(rawClaims)
	return out
}

func claimString(value any) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	default:
		return ""
	}
}

func claimStrings(value any) []string {
	switch v := value.(type) {
	case nil:
		return []string{}
	case string:
		if strings.TrimSpace(v) == "" {
			return []string{}
		}
		return []string{v}
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s := claimString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		if s := claimString(v); s != "" {
			return []string{s}
		}
		return []string{}
	}
}

func flattenClaim(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	if s := claimString(value); s != "" {
		return s, true
	}
	if list := claimStrings(value); len(list) > 0 {
		return strings.Join(list, ","), true
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}
