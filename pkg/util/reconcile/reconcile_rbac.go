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

package reconcile

import (
	"context"

	rbacv1 "github.com/kvdi/kvdi/apis/rbac/v1"
	"github.com/kvdi/kvdi/pkg/util/k8sutil"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	krbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ServiceAccount will ensure a service account in the cluster
func ServiceAccount(ctx context.Context, reqLogger logr.Logger, c client.Client, acct *corev1.ServiceAccount) error {
	found := &corev1.ServiceAccount{}
	if err := c.Get(ctx, types.NamespacedName{Name: acct.Name, Namespace: acct.Namespace}, found); err != nil {
		// Return API error
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		// Create the service account
		reqLogger.Info("Creating new service account", "ServiceAccount.Name", acct.Name, "ServiceAccount.Namespace", acct.Namespace)
		if err := c.Create(ctx, acct); err != nil {
			return err
		}
	}
	return nil
}

// ClusterRole will ensure a ClusterRole with the cluster.
func ClusterRole(ctx context.Context, reqLogger logr.Logger, c client.Client, role *krbacv1.ClusterRole) error {
	if err := k8sutil.SetCreationSpecAnnotation(&role.ObjectMeta, role); err != nil {
		return err
	}
	found := &krbacv1.ClusterRole{}
	if err := c.Get(ctx, types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, found); err != nil {
		// Return API error
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		// Create the role
		reqLogger.Info("Creating new cluster role ", "Name", role.Name)
		if err := c.Create(ctx, role); err != nil {
			return err
		}
		return nil
	}

	// Check the found role spec
	if !k8sutil.CreationSpecsEqual(role.ObjectMeta, found.ObjectMeta) {
		// We need to update the role
		reqLogger.Info("Role annotation spec has changed, updating", "Name", role.Name)
		found.Rules = role.Rules
		found.SetAnnotations(role.GetAnnotations())
		if err := c.Update(ctx, found); err != nil {
			return err
		}
		return nil
	}

	return nil
}

// ClusterRoleBinding will ensure a cluster role binding.
func ClusterRoleBinding(ctx context.Context, reqLogger logr.Logger, c client.Client, roleBinding *krbacv1.ClusterRoleBinding) error {
	if err := k8sutil.SetCreationSpecAnnotation(&roleBinding.ObjectMeta, roleBinding); err != nil {
		return err
	}
	found := &krbacv1.ClusterRoleBinding{}
	if err := c.Get(ctx, types.NamespacedName{Name: roleBinding.Name, Namespace: roleBinding.Namespace}, found); err != nil {
		// Return API error
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		// Create the role binding
		reqLogger.Info("Creating new cluster role binding", "Name", roleBinding.Name)
		if err := c.Create(ctx, roleBinding); err != nil {
			return err
		}
		return nil
	}

	// Check the found role binding spec
	if !k8sutil.CreationSpecsEqual(roleBinding.ObjectMeta, found.ObjectMeta) {
		// We need to update the role binding
		reqLogger.Info("Role binding annotation spec has changed, updating", "Name", roleBinding.Name)
		found.Subjects = roleBinding.Subjects
		found.RoleRef = roleBinding.RoleRef
		found.SetAnnotations(roleBinding.GetAnnotations())
		if err := c.Update(ctx, found); err != nil {
			return err
		}
		return nil
	}

	return nil
}

// Role will ensure a namespaced Role with the cluster.
func Role(ctx context.Context, reqLogger logr.Logger, c client.Client, role *krbacv1.Role) error {
	if err := k8sutil.SetCreationSpecAnnotation(&role.ObjectMeta, role); err != nil {
		return err
	}
	found := &krbacv1.Role{}
	if err := c.Get(ctx, types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, found); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		reqLogger.Info("Creating new role", "Name", role.Name, "Namespace", role.Namespace)
		return c.Create(ctx, role)
	}

	if !k8sutil.CreationSpecsEqual(role.ObjectMeta, found.ObjectMeta) {
		reqLogger.Info("Role annotation spec has changed, updating", "Name", role.Name, "Namespace", role.Namespace)
		found.Rules = role.Rules
		found.SetAnnotations(role.GetAnnotations())
		return c.Update(ctx, found)
	}

	return nil
}

// RoleBinding will ensure a namespaced role binding.
func RoleBinding(ctx context.Context, reqLogger logr.Logger, c client.Client, roleBinding *krbacv1.RoleBinding) error {
	if err := k8sutil.SetCreationSpecAnnotation(&roleBinding.ObjectMeta, roleBinding); err != nil {
		return err
	}
	found := &krbacv1.RoleBinding{}
	if err := c.Get(ctx, types.NamespacedName{Name: roleBinding.Name, Namespace: roleBinding.Namespace}, found); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		reqLogger.Info("Creating new role binding", "Name", roleBinding.Name, "Namespace", roleBinding.Namespace)
		return c.Create(ctx, roleBinding)
	}

	if !k8sutil.CreationSpecsEqual(roleBinding.ObjectMeta, found.ObjectMeta) {
		reqLogger.Info("Role binding annotation spec has changed, updating", "Name", roleBinding.Name, "Namespace", roleBinding.Namespace)
		found.Subjects = roleBinding.Subjects
		found.RoleRef = roleBinding.RoleRef
		found.SetAnnotations(roleBinding.GetAnnotations())
		return c.Update(ctx, found)
	}

	return nil
}

// VDIRole reconciles a VDIRole with the cluster.
func VDIRole(ctx context.Context, reqLogger logr.Logger, c client.Client, role *rbacv1.VDIRole) error {
	if err := k8sutil.SetCreationSpecAnnotation(&role.ObjectMeta, role); err != nil {
		return err
	}
	found := &rbacv1.VDIRole{}
	if err := c.Get(ctx, types.NamespacedName{Name: role.Name, Namespace: metav1.NamespaceAll}, found); err != nil {
		// Return API error
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		// Create the role
		reqLogger.Info("Creating new VDI role ", "Name", role.Name)
		if err := c.Create(ctx, role); err != nil {
			return err
		}
		return nil
	}

	// Check the found role spec
	if !k8sutil.CreationSpecsEqual(role.ObjectMeta, found.ObjectMeta) {
		// We need to update the role
		reqLogger.Info("Role annotation spec has changed, updating", "Name", role.Name)
		found.Rules = role.Rules
		found.SetLabels(role.GetLabels())
		found.SetAnnotations(role.GetAnnotations())
		if err := c.Update(ctx, found); err != nil {
			return err
		}
		return nil
	}

	return nil
}
