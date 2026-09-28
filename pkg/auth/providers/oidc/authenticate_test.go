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
	"testing"

	appv1 "github.com/kvdi/kvdi/apis/app/v1"
	"github.com/kvdi/kvdi/pkg/secrets"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestProvider(t *testing.T) *AuthProvider {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := appv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	cluster := &appv1.VDICluster{}
	cluster.Name = "test-cluster"
	engine := secrets.GetSecretEngine(cluster)
	if err := engine.Setup(c, cluster); err != nil {
		t.Fatal(err)
	}
	return &AuthProvider{client: c, cluster: cluster, secrets: engine}
}

func TestBindUsernameToSubject(t *testing.T) {
	a := newTestProvider(t)
	if err := a.bindUsernameToSubject("alice", "https://idp.example", "sub-alice"); err != nil {
		t.Fatal("expected first binding to succeed, got", err)
	}
	if err := a.bindUsernameToSubject("alice", "https://idp.example", "sub-alice"); err != nil {
		t.Fatal("expected same identity to be accepted, got", err)
	}
	if err := a.bindUsernameToSubject("alice", "https://idp.example", "sub-mallory"); err == nil {
		t.Fatal("expected a different subject claiming the same username to be rejected")
	}
	if err := a.bindUsernameToSubject("alice", "https://other-idp.example", "sub-alice"); err == nil {
		t.Fatal("expected a different issuer claiming the same username to be rejected")
	}
	if err := a.bindUsernameToSubject("bob", "https://idp.example", ""); err == nil {
		t.Fatal("expected an empty subject to be rejected")
	}
}

func TestGetUsernameFromClaims(t *testing.T) {
	tests := []struct {
		name    string
		claims  map[string]interface{}
		want    string
		wantErr bool
	}{
		{"preferred username", map[string]interface{}{"preferred_username": "alice", "email": "x@y"}, "alice", false},
		{"verified email", map[string]interface{}{"email": "alice@corp.example", "email_verified": true}, "alice", false},
		{"email without verified claim", map[string]interface{}{"email": "alice@corp.example"}, "alice", false},
		{"unverified email", map[string]interface{}{"email": "alice@attacker.example", "email_verified": false}, "", true},
		{"malformed verified claim", map[string]interface{}{"email": "alice@attacker.example", "email_verified": "true"}, "", true},
		{"no usable claims", map[string]interface{}{"sub": "123"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getUsernameFromClaims(tt.claims)
			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error state: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
