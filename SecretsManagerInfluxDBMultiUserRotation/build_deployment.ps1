# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Ensure that binary is installed in the local environment
Function check_command_installed ($Command) {
    if (-Not (Get-Command $Command -errorAction SilentlyContinue))
    {
        Write-Output "$Command could not be found, please install it and re-run this script."
        exit 1
    }
}

# Get user input to verify that the binary installed has the expected path value
Function binary_input_verification ($BinaryName, $BinaryPath) {
    Write-Host "This script uses $BinaryName with the following absolute path:"
    Write-Host $BinaryPath 
    Write-Host "If this is the expected path for $BinaryName then type 'y' to continue: "
    $continue_confirmation = Read-Host -Prompt "y/n"

    if (-Not ([string]$continue_confirmation -eq "y"))
    {
        Write-Host "Script Aborted"
        exit 1
    }
}

# Output the help dialogue for how to use this script
Function show_help_dialogue()
{
    Write-Output "
        Usage: build_deployment.ps1 [-F Format] [-L Linter] [-D Deploy]

        -F Format       Run the ruff formatter.
        -L Linter       Run the ruff linter.
        -D Deploy       Build and package the deployment.

        For Example: ./build_deployment.ps1 -D
    "
}

if ($($args.Count) -eq 0)
{
    show_help_dialogue
    exit 1
}

ForEach ($arg in $args) {
    switch -Exact ($arg)
    {
        {($_ -eq "-F") -or ($_ -eq "-L")}
        {
            check_command_installed "ruff";
            $ruff_installed_path=$(Get-Command "ruff").Source
            binary_input_verification "ruff" $ruff_installed_path
            if ($_ -eq "-F")
            {
                Write-Output "Running Formatter";
                ruff format
            }
            else
            {
                Write-Output "Running Linter";
                ruff check
            }
            exit 1            
        }
        {($_ -eq "-D")} 
        {
            Write-Output "Building Deployment";
            break
        }
        Default 
        {
            Write-Output "Invalid option: $arg";
            exit 1
        }
    }
}

# Ensure pip3 is installed and verify the binary location
check_command_installed "pip3"
$pip3_installed_path=$(Get-Command "pip3").Source
binary_input_verification "pip3" $pip3_installed_path

# Make a temporary directory and populate with dependencies
mkdir tmp-influxdb-deployment-lambda
cd tmp-influxdb-deployment-lambda
pip3 install -r ..\requirements.txt -t . --no-user

# Copy the lambda function code and create a zip of lambda with dependencies
copy ..\lambda_function.py .\
Compress-Archive -Path * -DestinationPath ..\influxdb-token-rotation-lambda.zip -CompressionLevel Optimal -Force

# Cleanup
cd ..\
Remove-Item -Path .\tmp-influxdb-deployment-lambda -Force -Recurse
