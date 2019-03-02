#!/usr/bin/env bash

. scripts/kube_common

kubectl create serviceaccount --namespace kube-system tiller
kubectl create clusterrolebinding tiller-cluster-role --clusterrole=cluster-admin --serviceaccount=kube-system:tiller

curl -fsSL https://raw.githubusercontent.com/helm/helm/master/scripts/get | bash
helm init --service-account tiller

wait_for_pod "Tiller" kube-system app=helm,name=tiller
