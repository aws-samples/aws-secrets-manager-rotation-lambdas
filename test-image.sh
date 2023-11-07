#!/bin/bash

set -euo pipefail
set -x 

image_uri=${1}

if [[ ! -d ~/.aws-lambda-rie ]]; then
  mkdir ~/.aws-lambda-rie
  curl -Lo ~/.aws-lambda-rie/aws-lambda-rie https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie
  chmod +x ~/.aws-lambda-rie/aws-lambda-rie
fi

docker run -d --rm -p 9000:8080 \
  -v ~/.aws-lambda-rie:/aws-lambda \
  --entrypoint /aws-lambda/aws-lambda-rie \
  $image_uri \
  /aws-lambda/aws-lambda-rie python -m awslambdaric lambda_function.lambda_handler
