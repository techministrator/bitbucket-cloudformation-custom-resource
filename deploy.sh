#!/bin/bash

STACK_NAME=${1:-'bitbucket-repo-custom-resource'}
REGION=${2:-'ap-southeast-1'}
TEMPLATE_NAME="${STACK_NAME}.yml"
ARTIFACT_BUCKET='your-artifact-bucket-name'

aws sts get-caller-identity
if [[ "$?" == 253 ]]; then 
  echo 'Please specify profile using either AWS_PROFILE, AWS_DEFAULT_PROFILE or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN.'
  exit 1
fi

if [[ ! $(aws cloudformation validate-template --template-body file://${TEMPLATE_NAME} --region $REGION) ]]; then
  echo 'Template error, please check again'
  exit 1
fi

if [ -d src/main/package ]; then rm -rf src/main/package; fi
mkdir src/main/package/
cp src/main/*.py src/main/package/
cp src/main/requirements.txt src/main/package/
pip install -r src/main/package/requirements.txt -t src/main/package/

sam deploy --template-file ${TEMPLATE_NAME} --stack-name ${STACK_NAME} --capabilities CAPABILITY_NAMED_IAM --s3-bucket ${ARTIFACT_BUCKET} --region ${REGION}
