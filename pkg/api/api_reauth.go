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
	"net/http"

	"github.com/kvdi/kvdi/pkg/types"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
	"github.com/kvdi/kvdi/pkg/util/errors"
)

// requiresReauth returns true when the request targets the calling user's own
// account and the auth provider supports password re-verification.
func (d *desktopAPI) requiresReauth(r *http.Request, targetUser string) bool {
	if d.vdiCluster.IsUsingOIDCAuth() {
		return false
	}
	session := apiutil.GetRequestUserSession(r)
	return session != nil && session.User != nil && session.User.GetName() == targetUser
}

// verifyCurrentPassword re-authenticates the user with the supplied current
// password. It writes an error response and returns false on failure.
func (d *desktopAPI) verifyCurrentPassword(w http.ResponseWriter, r *http.Request, username, currentPassword string) bool {
	if currentPassword == "" {
		apiutil.ReturnAPIError(errors.New("'currentPassword' is required for this operation"), w)
		return false
	}
	req := &types.LoginRequest{Username: username, Password: currentPassword}
	req.SetRequest(r)
	if _, err := d.auth.Authenticate(req); err != nil {
		apiutil.ReturnAPIForbidden(err, "Invalid credentials", w)
		return false
	}
	return true
}
