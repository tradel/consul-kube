#!/usr/bin/env bash

. scripts/kube_common

kubectl create -f data/consul-pv.yaml

helm repo add consul https://consul-helm-charts.storage.googleapis.com
helm install --name=consul consul/consul -f data/consul-values.yaml

wait_for_pod "Consul server" default app=consul,component=server
wait_for_pod "Consul clients" default app=consul,component=client
wait_for_pod "Consul Connect injector" default app=consul,component=connect-injector

kubectl port-forward service/consul-ui 8500:80 &
