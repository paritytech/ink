#!/bin/bash

# This script is mostly copied from https://github.com/paritytech/polkadot/blob/master/scripts/gitlab/trigger_pipeline.sh.

set -eu

# API trigger another project's pipeline
echo "Triggering ink-waterfall pipeline."

echo "https://${CI_SERVER_HOST}/api/v4/projects/${DWNSTRM_ID}/trigger/pipeline"

curl \
    -X POST \
    -F "token=${CI_JOB_TOKEN}" \
    -F "variables[TRGR_PROJECT]=${TRGR_PROJECT}" \
    -F "variables[TRGR_REF]=${TRGR_REF}" \
    -F "variables[IMAGE_NAME]=${IMAGE_NAME}" \
    -F "variables[IMAGE_TAG]=${IMAGE_TAG}" \
    "https://${CI_SERVER_HOST}/api/v4/projects/${DWNSTRM_ID}/trigger/pipeline"

curl --silent \
    -X POST \
    -F "token=${CI_JOB_TOKEN}" \
    -F "variables[TRGR_PROJECT]=${TRGR_PROJECT}" \
    -F "variables[TRGR_REF]=${TRGR_REF}" \
    "https://${CI_SERVER_HOST}/api/v4/projects/${DWNSTRM_ID}/trigger/pipeline" | \
        tee pipeline;

    #-F "variables[IMAGE_NAME]=${IMAGE_NAME}" \
    #-F "variables[IMAGE_TAG]=${IMAGE_TAG}" \
    #-F "variables[UPSTREAM_PR_ID]=${UPSTREAM_PR_ID}" \
    #-F "ref=v3" `# trigger the pinned version of simnet CI config` \

PIPELINE_ID=$(cat pipeline | jq ".id")
PIPELINE_URL=$(cat pipeline | jq ".web_url")
echo
echo "ink-waterfall pipeline ${PIPELINE_URL} was successfully triggered."
echo "Now we're polling it to obtain the distinguished status."

# This is a workaround for a Gitlab bug, waits here until
# https://gitlab.com/gitlab-org/gitlab/-/issues/326137 gets fixed.
# The timeout is 360 curls with 8 sec interval, roughly an hour.

function get_status() {
    curl --silent \
        --header "PRIVATE-TOKEN: ${PIPELINE_TOKEN}" \
        "https://${CI_SERVER_HOST}/api/v4/projects/${DWNSTRM_ID}/pipelines/${PIPELINE_ID}" | \
            jq --raw-output ".status";
}

echo "Waiting on ${PIPELINE_ID} status..."

for i in $(seq 1 360); do
    STATUS=$(get_status);
    echo "Triggered pipeline status is ${STATUS}";
    if [[ ${STATUS} =~ ^(pending|running|created)$ ]]; then
        echo;
    elif [[ ${STATUS} =~ ^(failed|canceled|skipped|manual)$ ]]; then
        echo "Something's broken in: ${PIPELINE_URL}"; exit 1;
    elif [[ ${STATUS} =~ ^(success)$ ]]; then
        echo "Look how green it is: ${PIPELINE_URL}"; exit 0;
    else
        echo "Something else has happened in ${PIPELINE_URL}"; exit 1;
    fi
sleep 8;
done
