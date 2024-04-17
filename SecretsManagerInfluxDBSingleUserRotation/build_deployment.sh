#!/bin/bash
#
# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Ensure that binary is installed in the local environment
check_command_installed () {
    bin_path=$(command -v $1)
    if [ "${bin_path}" == "" ];
    then
        echo "$1 could not be found, please install it and re-run this script." >&2
        exit 1
    fi
    echo "$bin_path"
}

# Output the help dialogue for how to use this script
show_help_dialogue()
{
echo "
        Usage: build_deployment.sh [-F Format] [-L Linter] [-D Deploy]

        -F Format       Run the ruff formatter.
        -L Linter       Run the ruff linter.
        -D Deploy       Build and package the deployment.

        For Example: ./build_deployment.sh -D
"
}

if [ $# -eq 0 ]
then
  show_help_dialogue
  exit 1
fi

while getopts "FLD" flag; do
  case $flag in
    F|L)
      ruff_bin_path="$(check_command_installed "ruff")"
      [ -z "${ruff_bin_path}" ] && exit 1
      echo "This script uses the ruff binary with the following absolute path:"
      echo "$ruff_bin_path"
      read -p "If this is the expected path for this binary type 'y' to continue: " -r
      if [ "$flag" == "F" ]
      then
        echo "Running Formatter"
        format_result=$(ruff format)
        echo "$format_result"
      else
        echo "Running Linter"
        lint_result=$(ruff check)
        echo "$lint_result"
      fi
      exit 1
      ;;
    D)
      echo "Building Deployment"
      ;;
    \?)
      echo "Invalid option: -$flag"
      exit 1
      ;;
  esac
done

# Ensure pip3 and zip is installed
pip3_bin_path="$(check_command_installed "pip3")"
[ -z "${pip3_bin_path}" ] && exit 1
zip_bin_path="$(check_command_installed "zip")"
[ -z "${zip_bin_path}" ] && exit 1

# Verify the installed binary locations are in the expected locations
echo "This script uses pip3 and zip binaries with the following absolute paths:"
echo "$pip3_bin_path"
echo "$zip_bin_path"
read -p "If these are the expected paths for these binaries type 'y' to continue: " -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Script Aborted"
    exit 1
fi

# Make a temporary directory and populate with dependencies
mkdir tmp-influxdb-deployment-lambda
cd tmp-influxdb-deployment-lambda
pip3 install -r ../requirements.txt -t .

# Copy the lambda function code and create a zip of lambda with dependencies
cp ../lambda_function.py ./

zip -r ../influxdb-token-rotation-lambda.zip .

# Cleanup
cd ../
rm -rf tmp-influxdb-deployment-lambda
