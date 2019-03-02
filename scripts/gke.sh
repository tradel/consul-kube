#!/bin/bash

set -e

if [[ ! -d "$HOME/google-cloud-sdk/bin" ]]; then
    rm -rf $HOME/google-cloud-sdk
    export CLOUDSDK_CORE_DISABLE_PROMPTS=1
    curl https://sdk.cloud.google.com | bash
fi

source $HOME/google-cloud-sdk/path.bash.inc
gcloud --quiet version
gcloud --quiet components update
gcloud --quiet components update kubectl


echo $GCLOUD_SERVICE_KEY | base64 --decode > ${HOME}/gcloud-service-key.json
gcloud auth activate-service-account --key-file ${HOME}/gcloud-service-key.json

scopes="https://www.googleapis.com/auth/devstorage.read_only,
        https://www.googleapis.com/auth/logging.write,
        https://www.googleapis.com/auth/monitoring,
        https://www.googleapis.com/auth/servicecontrol,
        https://www.googleapis.com/auth/service.management.readonly,
        https://www.googleapis.com/auth/trace.append"

scopes=$(echo $scopes | sed -e 's/ *//g')

gcloud beta container --project ${PROJECT_NAME} clusters create ${CLUSTER_NAME} \
    --zone ${CLOUDSDK_COMPUTE_ZONE} --username "admin" \
    --cluster-version "1.11.7-gke.4" --image-type "COS" \
    --machine-type "n1-standard-4" --num-nodes "1" --disk-type "pd-standard" --disk-size "100" \
    --scopes $scopes --enable-cloud-logging --enable-cloud-monitoring \
    --no-enable-ip-alias --network "projects/gke-helm-consul-ent/global/networks/default" \
    --subnetwork "projects/gke-helm-consul-ent/regions/us-east1/subnetworks/default" \
    --addons HorizontalPodAutoscaling,HttpLoadBalancing,KubernetesDashboard \
    --enable-autoupgrade --enable-autorepair

gcloud --quiet config set project ${PROJECT_NAME}
gcloud --quiet config set container/cluster ${CLUSTER_NAME}
gcloud --quiet config set compute/zone ${CLOUDSDK_COMPUTE_ZONE}
gcloud --quiet container clusters get-credentials ${CLUSTER_NAME}
