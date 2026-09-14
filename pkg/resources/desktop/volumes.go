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

	appv1 "github.com/kvdi/kvdi/apis/app/v1"
	desktopsv1 "github.com/kvdi/kvdi/apis/desktops/v1"
	"github.com/kvdi/kvdi/pkg/util/errors"
	"github.com/kvdi/kvdi/pkg/util/k8sutil"
	"github.com/kvdi/kvdi/pkg/util/reconcile"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (f *Reconciler) reconcileVolumes(ctx context.Context, reqLogger logr.Logger, cluster *appv1.VDICluster, instance *desktopsv1.Session) error {
	volMapCM, err := f.getVolMapForCluster(cluster)
	if err != nil {
		return err
	}
	var existingVol string
	var ok bool
	if existingVol, ok = volMapCM.Data[instance.GetUser()]; ok {
		reqLogger.Info("Fetching existing volume for user")
		pv := &corev1.PersistentVolume{}
		if err := f.client.Get(ctx, types.NamespacedName{Name: existingVol, Namespace: metav1.NamespaceAll}, pv); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return err
			}
			reqLogger.Info("The volume referenced in the userdata configmap no longer exists, creating a new one")
			existingVol = ""
		} else if err := f.reservePVForInstance(reqLogger, cluster, instance, pv); err != nil {
			return err
		}
	}
	pvc := newPVCForUser(cluster, instance, existingVol)
	return reconcile.PersistentVolumeClaim(ctx, reqLogger, f.client, pvc)
}

// reservePVForInstance points the user's retained volume at the PVC that is
// about to be created for this session so that it, and only it, can bind.
// If the volume is still bound to an existing claim it is left alone.
func (f *Reconciler) reservePVForInstance(reqLogger logr.Logger, cluster *appv1.VDICluster, instance *desktopsv1.Session, pv *corev1.PersistentVolume) error {
	ref := &corev1.ObjectReference{
		Namespace: instance.GetNamespace(),
		Name:      cluster.GetUserdataVolumeName(instance.GetUser()),
	}
	if claimRefMatches(pv.Spec.ClaimRef, ref) {
		return nil
	}
	if exists, err := f.pvClaimExists(pv); err != nil {
		return err
	} else if exists {
		reqLogger.Info("Existing volume for user is still bound to another claim, not re-reserving")
		return nil
	}
	reqLogger.Info("Reserving existing volume for this session's claim")
	_, err := f.reservePV(pv, ref)
	return err
}

func (f *Reconciler) reconcileUserdataMapping(ctx context.Context, reqLogger logr.Logger, cluster *appv1.VDICluster, instance *desktopsv1.Session) error {

	pvc, err := f.getPVCForInstance(cluster, instance)
	if err != nil {
		return err
	}

	if pvc.Spec.VolumeName == "" {
		return errors.NewRequeueError("PVC has not had its volume provisioned yet", 3)
	}

	pvName := pvc.Spec.VolumeName

	pv, err := f.getPV(pvName)
	if err != nil {
		return err
	}

	// it won't harm the running instance and the storage class provider may
	// leave us alone
	if _, err := f.retainPV(pv); err != nil {
		return err
	}

	volMapCM, err := f.getVolMapForCluster(cluster)
	if err != nil {
		return err
	}

	if volMapCM.Data == nil {
		volMapCM.Data = make(map[string]string)
	}

	if pv, ok := volMapCM.Data[instance.GetUser()]; !ok || pv != pvName {
		volMapCM.Data[instance.GetUser()] = pvName
		if err := f.client.Update(ctx, volMapCM); err != nil {
			return err
		}
	}

	return nil
}

func newConfigMapForCluster(cluster *appv1.VDICluster) *corev1.ConfigMap {
	nn := cluster.GetUserdataVolumeMapName()
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            nn.Name,
			Namespace:       nn.Namespace,
			Labels:          cluster.GetComponentLabels("userdata-map"),
			OwnerReferences: cluster.OwnerReferences(),
		},
		Data: make(map[string]string),
	}
}

func newPVCForUser(cluster *appv1.VDICluster, instance *desktopsv1.Session, existingPVName string) *corev1.PersistentVolumeClaim {
	spec := cluster.GetUserdataVolumeSpec()
	if existingPVName != "" {
		spec.VolumeName = existingPVName
	}
	var ownerReferences []metav1.OwnerReference
	if !cluster.RetainPVCs() {
		ownerReferences = instance.OwnerReferences()
	}
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:            cluster.GetUserdataVolumeName(instance.GetUser()),
			Namespace:       instance.GetNamespace(),
			Labels:          k8sutil.GetDesktopLabels(cluster, instance),
			OwnerReferences: ownerReferences,
		},
		Spec: *spec,
	}
}
