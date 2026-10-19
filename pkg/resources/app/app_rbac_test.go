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

package app

import (
	"testing"

	appv1 "github.com/kvdi/kvdi/apis/app/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func ruleGrants(rules []rbacv1.PolicyRule, resource, verb string) bool {
	for _, rule := range rules {
		for _, res := range rule.Resources {
			if res != resource {
				continue
			}
			for _, v := range rule.Verbs {
				if v == verb || v == "*" {
					return true
				}
			}
		}
	}
	return false
}

func TestAppClusterRoleDoesNotGrantClusterWideSecretAccess(t *testing.T) {
	cluster := &appv1.VDICluster{}
	cluster.Name = "test"
	role := newAppClusterRoleForCR(cluster)
	for _, resource := range []string{"secrets", "configmaps"} {
		for _, verb := range []string{"get", "list", "watch", "update", "patch", "delete"} {
			if ruleGrants(role.Rules, resource, verb) {
				t.Errorf("app ClusterRole must not grant %s on %s cluster-wide", verb, resource)
			}
		}
	}
	if !ruleGrants(role.Rules, "secrets", "create") {
		t.Error("app ClusterRole must still allow creating session env secrets")
	}
}

func TestAppRoleIsScopedToCoreNamespace(t *testing.T) {
	cluster := &appv1.VDICluster{}
	cluster.Name = "test"
	cluster.Spec.AppNamespace = "kvdi-core"
	role := newAppRoleForCR(cluster)
	if role.Namespace != "kvdi-core" {
		t.Errorf("expected role in kvdi-core, got %q", role.Namespace)
	}
	for _, resource := range []string{"secrets", "configmaps"} {
		if !ruleGrants(role.Rules, resource, "get") {
			t.Errorf("expected namespaced role to grant get on %s", resource)
		}
	}
	rb := newAppRoleBindingForCR(cluster)
	if rb.Namespace != "kvdi-core" || rb.RoleRef.Kind != "Role" || rb.RoleRef.Name != role.Name {
		t.Errorf("unexpected role binding: %+v", rb)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != cluster.GetAppName() || rb.Subjects[0].Namespace != "kvdi-core" {
		t.Errorf("unexpected role binding subjects: %+v", rb.Subjects)
	}
}
