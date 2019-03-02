#!/bin/bash

. scripts/kube_common

# Deploy a simple HTTP echo service
kubectl create -f data/echo-server.yaml
wait_for_pod "HTTP echo server" default app=http-echo,role=server

# Deploy a client for the echo service
kubectl create -f data/echo-client.yaml
wait_for_pod "HTTP echo client" default app=http-echo,role=client

