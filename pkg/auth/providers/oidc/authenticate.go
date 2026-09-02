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

package oidc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	v1 "github.com/kvdi/kvdi/apis/meta/v1"
	rbacv1 "github.com/kvdi/kvdi/apis/rbac/v1"
	"github.com/kvdi/kvdi/pkg/types"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
	"github.com/kvdi/kvdi/pkg/util/common"
	"github.com/kvdi/kvdi/pkg/util/errors"
	"github.com/kvdi/kvdi/pkg/util/rbac"
)

const (
	// how long a client has to return from the provider after being redirected
	pendingFlowTTL = 10 * time.Minute
	// how long authorized claims can be redeemed after the provider callback
	authorizedClaimsTTL = 2 * time.Minute
)

// stateRecord is what gets persisted in the secrets backend for an in-flight
// OIDC flow. Result is nil until the provider callback has been verified.
type stateRecord struct {
	Nonce     string            `json:"nonce"`
	ExpiresAt time.Time         `json:"expiresAt"`
	Result    *types.AuthResult `json:"result,omitempty"`
}

func (s *stateRecord) expired() bool { return time.Now().After(s.ExpiresAt) }

// Authenticate is called for API authentication requests. It should generate
// a new JWTClaims object and serve an AuthResult back to the API.
func (a *AuthProvider) Authenticate(req *types.LoginRequest) (*types.AuthResult, error) {
	r := req.GetRequest()

	// POST methods are the start and end of an oidc flow. If we recorded verified claims
	// for the provided state we return them back to the API. Otherwise, we start a new flow
	// with the provided state.
	if r.Method == http.MethodPost {
		if req.GetState() == "" {
			return nil, errors.New("No 'state' provided in the request")
		}
		stateKey := getStateSecretKey(req.GetState())
		record, err := a.readStateRecord(stateKey)
		if err != nil {
			return nil, err
		}
		if record == nil || record.Result == nil || record.expired() {
			// No verified claims for this state (never started, still pending, or stale):
			// register a fresh flow and return the oauth redirect.
			return a.startFlow(stateKey, req.GetState())
		}
		// claims are single-use, clear the state secret for this auth session
		if err := a.deleteStateRecord(stateKey); err != nil {
			return nil, err
		}
		return record.Result, nil
	}

	// GET is the middle part of the oauth flow. This is to trick the client into
	// sending another post to retrieve its token.

	state := r.URL.Query().Get("state")
	if state == "" {
		return nil, errors.New("No 'state' provided in the callback")
	}
	stateKey := getStateSecretKey(state)

	// the callback must belong to a flow this server started and that has not yet completed
	record, err := a.readStateRecord(stateKey)
	if err != nil {
		return nil, err
	}
	if record == nil || record.Result != nil || record.expired() {
		if record != nil {
			if err := a.deleteStateRecord(stateKey); err != nil {
				return nil, err
			}
		}
		return nil, errors.New("Unknown or expired 'state' in the callback")
	}

	// get the oauth token from the provider
	oauth2Token, err := a.oauthCfg.Exchange(a.ctx, r.URL.Query().Get("code"))
	if err != nil {
		return nil, err
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("No 'id_token' returned by the provider")
	}

	// Parse and verify ID Token payload.
	idToken, err := a.verifier.Verify(a.ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	// the ID token must have been issued for the nonce bound to this state
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(record.Nonce)) != 1 {
		return nil, errors.New("ID token nonce does not match the nonce for this flow")
	}

	// parse the claims from the token
	claims := make(map[string]interface{})
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	// start building a user from the claims object
	username, err := getUsernameFromClaims(claims)
	if err != nil {
		return nil, err
	}

	result := &types.AuthResult{
		User: &types.VDIUser{
			Name:  username,
			Roles: make([]*types.VDIUserRole, 0),
		},
		RefreshNotSupported: true,
	}

	// BADDDDD
	if a.cluster.PreserveOIDCTokens() {
		result.Data = map[string]string{
			"access_token":  oauth2Token.AccessToken,
			"token_type":    oauth2Token.TokenType,
			"refresh_token": oauth2Token.RefreshToken,
			"expiry":        oauth2Token.Expiry.Format(time.RFC3339),
		}
	}

	// check if we can handle group membership
	groups, ok := claims[a.cluster.GetOIDCGroupScope()]
	if !ok {
		// if we can't determine group membership, check if cluster configuration
		// allows the user in anyway.
		if a.cluster.AllowNonGroupedReadOnly() {
			result.User.Roles = []*types.VDIUserRole{rbac.VDIRoleToUserRole(a.cluster.GetLaunchTemplatesRole())}
			return nil, a.marshalClaimsToSecret(stateKey, result)
		}
		return nil, errors.New("No groups provided in claims and allow non-grouped users is set to false")
	}

	userGroupSlc, err := groupClaimToStringSlice(groups)
	if err != nil {
		return nil, err
	}

	// At this point we are ready to authorize the user
	roles, err := a.cluster.GetRoles(a.client)
	if err != nil {
		return nil, err
	}

	boundRoles := make([]string, 0)
	for _, role := range roles {
		boundRoles = appendRoleIfBound(boundRoles, userGroupSlc, role)
	}

	result.User.Roles = apiutil.FilterUserRolesByNames(roles, boundRoles)

	// save the claims to the secret backend, they will be retrieved on the next POST
	// for this state.
	return nil, a.marshalClaimsToSecret(stateKey, result)
}

// startFlow registers a pending flow for the given state with a fresh nonce and
// returns the redirect to the provider.
func (a *AuthProvider) startFlow(stateKey, state string) (*types.AuthResult, error) {
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	if err := a.writeStateRecord(stateKey, &stateRecord{
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(pendingFlowTTL),
	}); err != nil {
		return nil, err
	}
	return &types.AuthResult{
		// Use offline access to get a refresh token that we can use to generate new
		// internal access tokens for the user.
		RedirectURL: a.oauthCfg.AuthCodeURL(state, oauth2.AccessTypeOffline, gooidc.Nonce(nonce)),
	}, nil
}

func (a *AuthProvider) marshalClaimsToSecret(stateKey string, result *types.AuthResult) error {
	return a.writeStateRecord(stateKey, &stateRecord{
		ExpiresAt: time.Now().Add(authorizedClaimsTTL),
		Result:    result,
	})
}

// readStateRecord returns the record for the given key, or nil if none exists.
func (a *AuthProvider) readStateRecord(stateKey string) (*stateRecord, error) {
	data, err := a.secrets.ReadSecret(stateKey, true)
	if err != nil {
		if errors.IsSecretNotFoundError(err) {
			return nil, nil
		}
		return nil, err
	}
	record := &stateRecord{}
	if err := json.Unmarshal(data, record); err != nil {
		return nil, err
	}
	return record, nil
}

func (a *AuthProvider) writeStateRecord(stateKey string, record *stateRecord) error {
	out, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := a.secrets.Lock(15); err != nil {
		return err
	}
	defer a.secrets.Release()
	return a.secrets.WriteSecret(stateKey, out)
}

func (a *AuthProvider) deleteStateRecord(stateKey string) error {
	if err := a.secrets.Lock(15); err != nil {
		return err
	}
	defer a.secrets.Release()
	return a.secrets.WriteSecret(stateKey, nil)
}

func newNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func getStateSecretKey(state string) string {
	return fmt.Sprintf("oidc_%s", state)
}

func groupClaimToStringSlice(ifc interface{}) ([]string, error) {
	userGroupSlc, ok := ifc.([]interface{})
	if !ok {
		return nil, errors.New("Could not coerce groups claims to string slice")
	}
	out := make([]string, 0)
	for _, item := range userGroupSlc {
		i, ok := item.(string)
		if !ok {
			return nil, errors.New("Could not coerce slice item to string")
		}
		out = append(out, i)
	}
	return out, nil
}

func getUsernameFromClaims(claims map[string]interface{}) (string, error) {
	if preferred, ok := claims["preferred_username"]; ok {
		if prfStr, ok := preferred.(string); ok {
			return prfStr, nil
		}
	}
	if email, ok := claims["email"]; ok {
		if emailStr, ok := email.(string); ok {
			return strings.Split(emailStr, "@")[0], nil
		}
	}
	return "", fmt.Errorf("could not parse username from claims: %+v", claims)
}

func appendRoleIfBound(boundRoles, userGroups []string, role *rbacv1.VDIRole) []string {
	if annotations := role.GetAnnotations(); annotations != nil {
		if oidcGroupStr, ok := annotations[v1.OIDCGroupRoleAnnotation]; ok {
			oidcGroups := strings.Split(oidcGroupStr, v1.AuthGroupSeparator)
			for _, group := range oidcGroups {
				if group == "" {
					continue
				}
				if common.StringSliceContains(userGroups, group) {
					boundRoles = common.AppendStringIfMissing(boundRoles, role.GetName())
				}
			}
		}
	}
	return boundRoles
}
