#!/bin/bash

set -euo pipefail
set -x

registry_repo="${1:-ignored-not-pushed}"

for row in $(cat images.json | jq -r '.folders[] | @base64'); do
  _jq() {
    echo ${row} | base64 --decode | jq -r ${1}
  }

  folder=$(_jq '.folder')
  system_packages=$(_jq '.install_system_packages') # returns 'null' if key is not present
  python_packages=$(_jq '.python_packages')         # returns 'null' if key is not present
  tag=$(_jq '.tag')
  
  cp Dockerfile $folder

  registry_repo_cache="$registry_repo-buildx-cache"

  docker_push_arg="--push"
  docker_cache_to_arg="--cache-to type=registry,ref=$registry_repo_cache,mode=max"
  docker_cache_from_arg="--cache-from type=registry,ref=$registry_repo_cache"
  docker_cache_args="$docker_cache_to_arg $docker_cache_from_arg"

  if [[ "$registry_repo" == "ignored-not-pushed" ]] ; then
    docker_push_arg=""
    docker_cache_args="$docker_cache_from_arg"
  fi
  
  docker build \
    --build-arg "system_packages=$system_packages" \
    --build-arg "python_packages=$python_packages" \
    --tag "$registry_repo:$tag" $docker_push_arg $docker_cache_args \
    $folder
  
  rm $folder/Dockerfile
  
done