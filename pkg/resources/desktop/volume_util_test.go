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

package desktop

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestReservePV(t *testing.T) {
	r := newReconciler(t)
	cluster := newCluster(t)
	desktop := newDesktop(t)
	desktop.Spec.User = "alice"

	// a volume left over from a session that has been deleted
	pv := &corev1.PersistentVolume{}
	pv.Name = "alice-volume"
	pv.Spec.PersistentVolumeReclaimPolicy = corev1.PersistentVolumeReclaimDelete
	pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: "old-namespace", Name: cluster.GetUserdataVolumeName("alice"), UID: types.UID("gone")}
	if err := r.client.Create(context.TODO(), pv); err != nil {
		t.Fatal(err)
	}

	// reclaiming should retain the volume and keep it reserved for the user
	// rather than making it cluster-wide Available
	changed, err := r.reservePV(pv, userdataReservationRef(cluster, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected the pv to be updated")
	}
	if err := r.client.Get(context.TODO(), types.NamespacedName{Name: pv.Name, Namespace: metav1.NamespaceAll}, pv); err != nil {
		t.Fatal(err)
	}
	if pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain {
		t.Error("expected reclaim policy to be Retain, got", pv.Spec.PersistentVolumeReclaimPolicy)
	}
	if pv.Spec.ClaimRef == nil {
		t.Fatal("expected claimRef to be retained as a reservation, got nil")
	}
	if pv.Spec.ClaimRef.Namespace != cluster.GetCoreNamespace() || pv.Spec.ClaimRef.Name != cluster.GetUserdataVolumeName("alice") || pv.Spec.ClaimRef.UID != "" {
		t.Errorf("unexpected reservation claimRef: %+v", pv.Spec.ClaimRef)
	}

	// second call is a no-op
	if changed, err := r.reservePV(pv, userdataReservationRef(cluster, "alice")); err != nil {
		t.Fatal(err)
	} else if changed {
		t.Error("expected no change on second reservation")
	}

	// a new session in another namespace re-points the reservation at its PVC
	if err := r.reservePVForInstance(testLogger, cluster, desktop, pv); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Get(context.TODO(), types.NamespacedName{Name: pv.Name, Namespace: metav1.NamespaceAll}, pv); err != nil {
		t.Fatal(err)
	}
	if pv.Spec.ClaimRef.Namespace != desktop.GetNamespace() || pv.Spec.ClaimRef.Name != cluster.GetUserdataVolumeName("alice") {
		t.Errorf("expected claimRef to target the session PVC, got %+v", pv.Spec.ClaimRef)
	}

	// a volume still bound to a live claim is left alone
	livePVC := &corev1.PersistentVolumeClaim{}
	livePVC.Name = cluster.GetUserdataVolumeName("alice")
	livePVC.Namespace = "other-namespace"
	livePVC.UID = types.UID("live-claim")
	if err := r.client.Create(context.TODO(), livePVC); err != nil {
		t.Fatal(err)
	}
	pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: livePVC.Namespace, Name: livePVC.Name, UID: livePVC.GetUID()}
	if err := r.client.Update(context.TODO(), pv); err != nil {
		t.Fatal(err)
	}
	if err := r.reservePVForInstance(testLogger, cluster, desktop, pv); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Get(context.TODO(), types.NamespacedName{Name: pv.Name, Namespace: metav1.NamespaceAll}, pv); err != nil {
		t.Fatal(err)
	}
	if pv.Spec.ClaimRef.Namespace != livePVC.Namespace || pv.Spec.ClaimRef.UID != livePVC.GetUID() {
		t.Errorf("expected live claimRef to be preserved, got %+v", pv.Spec.ClaimRef)
	}
}
