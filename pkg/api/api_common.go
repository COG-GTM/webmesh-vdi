/*
Copyright 2020,2021 Avi Zimmerman

This file is part of kvdi.

kvdi is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

kvdi is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with kvdi.  If not, see <https://www.gnu.org/licenses/>.
*/

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"

	v1 "github.com/kvdi/kvdi/apis/meta/v1"
	proxyclient "github.com/kvdi/kvdi/pkg/proxyproto/client"
	"github.com/kvdi/kvdi/pkg/types"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
	"github.com/kvdi/kvdi/pkg/util/errors"
)

// TokenHeader is the HTTP header containing the user's access token
const TokenHeader = "X-Session-Token"

// RefreshTokenCookie is the cookie used to store a user's refresh token
const RefreshTokenCookie = "refreshToken"

// RefreshTokenCookiePath restricts the refresh cookie to the API routes that consume it.
const RefreshTokenCookiePath = "/api"

// refreshTokenRecord is the value stored in the secrets backend for each refresh token.
type refreshTokenRecord struct {
	User      string `json:"user"`
	ExpiresAt int64  `json:"expiresAt"`
}

func (r *refreshTokenRecord) expired(now time.Time) bool {
	return r.ExpiresAt <= now.Unix()
}

func newRefreshTokenCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    value,
		Path:     RefreshTokenCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// returnNewJWT will return a new JSON web token to the requestor.
func (d *desktopAPI) returnNewJWT(w http.ResponseWriter, result *types.AuthResult, authorized bool, state string) {
	// fetch the JWT signing secret
	secret, err := d.secrets.ReadSecret(v1.JWTSecretKey, true)
	if err != nil {
		apiutil.ReturnAPIError(err, w)
		return
	}

	// create a new token
	claims, newToken, err := apiutil.GenerateJWT(secret, result, authorized, d.vdiCluster.GetTokenDuration())
	if err != nil {
		apiutil.ReturnAPIError(err, w)
		return
	}

	if authorized && !result.RefreshNotSupported {
		// Generate a refresh token
		refreshToken, err := d.generateRefreshToken(result.User)
		if err != nil {
			apiutil.ReturnAPIError(err, w)
			return
		}
		// Set a Secure, HttpOnly, SameSite cookie scoped to the API and bounded to the
		// lifetime of the token itself.
		http.SetCookie(w, newRefreshTokenCookie(refreshToken, int(v1.RefreshTokenLifetime.Seconds())))
	}

	// return the token to the user
	apiutil.WriteJSON(&types.SessionResponse{
		Token:      newToken,
		ExpiresAt:  claims.ExpiresAt,
		Renewable:  !result.RefreshNotSupported,
		User:       result.User,
		Authorized: authorized,
		State:      state,
	}, w)
}

func (d *desktopAPI) generateRefreshToken(user *types.VDIUser) (string, error) {
	refreshToken := uuid.New().String()
	if err := d.secrets.Lock(10); err != nil {
		return "", err
	}
	defer d.secrets.Release()
	tokens, err := d.secrets.ReadSecretMap(v1.RefreshTokensSecretKey, false)
	if err != nil {
		if !errors.IsSecretNotFoundError(err) {
			return "", err
		}
		tokens = make(map[string][]byte)
	}
	now := time.Now()
	pruneRefreshTokens(tokens, now)
	record, err := json.Marshal(&refreshTokenRecord{
		User:      user.Name,
		ExpiresAt: now.Add(v1.RefreshTokenLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	tokens[refreshToken] = record
	return refreshToken, d.secrets.WriteSecretMap(v1.RefreshTokensSecretKey, tokens)
}

var errRefreshTokenNotFound = errors.New("The refresh token does not exist in the secret storage")

// lookupRefreshToken resolves and revokes a refresh token, returning the user it
// belongs to. Expired or unparseable records are treated as non-existent.
func (d *desktopAPI) lookupRefreshToken(refreshToken string) (string, error) {
	if err := d.secrets.Lock(10); err != nil {
		return "", err
	}
	defer d.secrets.Release()
	tokens, err := d.secrets.ReadSecretMap(v1.RefreshTokensSecretKey, false)
	if err != nil {
		if errors.IsSecretNotFoundError(err) {
			return "", errRefreshTokenNotFound
		}
		return "", err
	}
	pruneRefreshTokens(tokens, time.Now())
	raw, ok := tokens[refreshToken]
	delete(tokens, refreshToken)
	if err := d.secrets.WriteSecretMap(v1.RefreshTokensSecretKey, tokens); err != nil {
		return "", err
	}
	if !ok {
		return "", errRefreshTokenNotFound
	}
	record, _ := parseRefreshTokenRecord(raw)
	return record.User, nil
}

// revokeUserRefreshTokens removes every outstanding refresh token belonging to the user.
func (d *desktopAPI) revokeUserRefreshTokens(username string) error {
	if err := d.secrets.Lock(10); err != nil {
		return err
	}
	defer d.secrets.Release()
	tokens, err := d.secrets.ReadSecretMap(v1.RefreshTokensSecretKey, false)
	if err != nil {
		if errors.IsSecretNotFoundError(err) {
			return nil
		}
		return err
	}
	pruneRefreshTokens(tokens, time.Now())
	for token, raw := range tokens {
		if record, _ := parseRefreshTokenRecord(raw); record.User == username {
			delete(tokens, token)
		}
	}
	return d.secrets.WriteSecretMap(v1.RefreshTokensSecretKey, tokens)
}

func parseRefreshTokenRecord(raw []byte) (*refreshTokenRecord, bool) {
	record := &refreshTokenRecord{}
	if err := json.Unmarshal(raw, record); err != nil || record.User == "" || record.ExpiresAt == 0 {
		return nil, false
	}
	return record, true
}

// pruneRefreshTokens drops expired and legacy (no expiry) records from the map.
func pruneRefreshTokens(tokens map[string][]byte, now time.Time) {
	for token, raw := range tokens {
		record, ok := parseRefreshTokenRecord(raw)
		if !ok || record.expired(now) {
			delete(tokens, token)
		}
	}
}

func (d *desktopAPI) getDesktopProxyHost(r *http.Request) (string, error) {
	nn := apiutil.GetNamespacedNameFromRequest(r)
	found := &corev1.Service{}
	if err := d.client.Get(context.TODO(), nn, found); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", found.Spec.ClusterIP, v1.WebPort), nil
}

func (d *desktopAPI) getProxyClientForRequest(r *http.Request) (*proxyclient.Client, error) {
	endpointURL, err := d.getDesktopProxyHost(r)
	if err != nil {
		return nil, err
	}
	return proxyclient.New(apiLogger, endpointURL), nil
}

// Session response
// swagger:response sessionResponse
type swaggerSessionResponse struct {
	// in:body
	Body types.SessionResponse
}

// Success response
// swagger:response boolResponse
type swaggerBoolResponse struct {
	// in:body
	Body struct {
		Ok bool `json:"ok"`
	}
}

// A generic error response
// swagger:response error
type swaggerResponseError struct {
	// in:body
	Body errors.APIError
}
