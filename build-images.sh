#!/bin/bash

set -euo pipefail
set -x

default_not_pushed_repo=ignored-not-pushed/some-repo

registry_repo="${1:-$default_not_pushed_repo}"
repo_name=$(cut -d/ -f2- <<< $registry_repo)
registry_repo_cache="ghcr.io/$repo_name-buildx-cache"

if [[ "$registry_repo" == "$default_not_pushed_repo" ]] ; then
  registry_repo_cache="ghcr.io/jericop/$(basename $(pwd))-buildx-cache"
fi

buildx_builder=container

# Create buildx builder with access to host network (if not already created)
docker buildx use $buildx_builder > /dev/null 2>&1 || \
  docker buildx create --name $buildx_builder --driver docker-container --driver-opt network=host --use

for row in $(cat images.json | jq -r '.folders[] | @base64'); do
  _jq() {
    echo ${row} | base64 --decode | jq -r ${1}
  }

  folder=$(_jq '.folder')
  system_packages=$(_jq '.install_system_packages') # returns 'null' if key is not present
  python_packages=$(_jq '.python_packages')         # returns 'null' if key is not present
  tag=$(_jq '.tag')
  
  cp Dockerfile $folder

  docker_push_arg="--push"

  docker_cache_to_arg="--cache-to type=registry,ref=$registry_repo_cache:$tag,mode=max"
  docker_cache_from_arg="--cache-from type=registry,ref=$registry_repo_cache:$tag"
  docker_cache_args="$docker_cache_to_arg $docker_cache_from_arg"

  if [[ "$registry_repo" == "$default_not_pushed_repo" ]] ; then
    docker_push_arg=""
    docker_cache_args="$docker_cache_from_arg"
  fi
  
  docker build \
    --builder $buildx_builder \
    --build-arg "system_packages=$system_packages" \
    --build-arg "python_packages=$python_packages" \
    --tag "$registry_repo:$tag" $docker_push_arg $docker_cache_args \
    $folder
  
  rm $folder/Dockerfile
  
done