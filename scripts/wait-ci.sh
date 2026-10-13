#!/usr/bin/env bash
# Usage: scripts/wait-ci.sh <workflow file>
# Succeed only once the workflow has passed on HEAD (pushed to main), waiting for a run in progress,
# so that no version goes out to be followed by a "CI failed" mail.
set -euo pipefail
workflow=$1
head=$(git rev-parse HEAD)
short=${head:0:7}

# GitHub may not have started the run for a just-pushed commit yet.
run=
for _ in $(seq 12); do
    run=$(gh run list --workflow "$workflow" --branch main --commit "$head" --limit 1 \
        --json databaseId,status,url,conclusion --jq '.[] | "\(.databaseId) \(.status) \(.url) \(.conclusion)"')
    [ -n "$run" ] && break
    echo "wait-ci: no $workflow run for $short yet, retrying" >&2
    sleep 5
done
[ -n "$run" ] || { echo "wait-ci: no $workflow run for $short, nothing released" >&2; exit 1; }

read -r id status url conclusion <<<"$run"
if [ "$status" != completed ]; then
    echo "wait-ci: waiting for CI on $short $url"
    gh run watch "$id" --exit-status --compact >/dev/null \
        || { echo "wait-ci: CI failed, nothing released: $url" >&2; exit 1; }
elif [ "$conclusion" != success ]; then
    echo "wait-ci: CI on $short ended with \"$conclusion\", nothing released: $url" >&2
    exit 1
fi
echo "wait-ci: CI passed on $short"
