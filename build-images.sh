#!/bin/bash

registry_repo="$1"

for row in $(cat images.json | jq -r '.folders[] | @base64'); do
  _jq() {
    echo ${row} | base64 --decode | jq -r ${1}
  }

  folder=$(_jq '.folder')
  packages=$(_jq '.required_packages')
  tag=$(_jq '.tag')
  
  cp Dockerfile $folder
  
  docker buildx build \
    --build-arg "packages=$packages" \
    --platform linux/amd64,linux/arm64 \
    --tag "$registry_repo:$tag" \
    --push  $folder 
  
  rm $folder/Dockerfile
  
done