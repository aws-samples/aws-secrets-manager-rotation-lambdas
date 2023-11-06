FROM public.ecr.aws/lambda/python:3.11

ARG system_packages
ARG python_packages

# Install system package (if required). jq returns 'null' for keys not present
RUN if [[ ! -z "$system_packages" && "$system_packages" != "null" ]]; then yum install -y $system_packages; fi

# Install python packages (if required). jq returns 'null' for keys not present
RUN if [[ ! -z "$python_packages" && "$python_packages" != "null" ]]; then pip install $python_packages; fi

# Copy function code
COPY lambda_function.py ${LAMBDA_TASK_ROOT}

# Set the CMD to your handler (could also be done as a parameter override outside of the Dockerfile)
CMD [ "lambda_function.lambda_handler" ]