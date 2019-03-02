#!/usr/bin/env bash

set -e

. scripts/kube_common

export CNI_PLUGIN=calico
DIND_VERSION=${DIND_VERSION:-1.11}
DIND_FILENAME=dind-cluster-v${DIND_VERSION}.sh
DIND_SCRIPT=scripts/${DIND_FILENAME}
DIND_BASE_URL=https://github.com/kubernetes-sigs/kubeadm-dind-cluster/releases/download/v0.1.0/

if [[ ! -f ${DIND_SCRIPT} ]]; then
    curl -fsSL -o ${DIND_SCRIPT} ${DIND_BASE_URL}/${DIND_FILENAME}
fi

chmod +x ${DIND_SCRIPT}
${DIND_SCRIPT} up

wait_for_nodes

kubectl cluster-info
kubectl get nodes
