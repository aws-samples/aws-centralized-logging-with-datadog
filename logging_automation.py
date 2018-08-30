# Copyright 2008-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
# http://aws.amazon.com/apache2.0/
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

from __future__ import print_function
import boto3
import botocore
import time
import sys
import argparse
import json
import os
import base64

encrypted_token = os.environ['DD_KMS_API_KEY']
ddApiKey = boto3.client('kms').decrypt(CiphertextBlob=base64.b64decode(encrypted_token))['Plaintext']

def lambda_handler(event, context):
    access_to_billing = "DENY"
    if event['existing_accountid'] is None:
        print("Creating new account: " + event['account_name'] + " (" + event['account_email'] + ")")
        print("********************************")
        credentials = assume_role(event['masteraccount_id'], 'ST-S-Automation', None)
        account_id = create_account(event['account_name'], event['account_email'], 'OrganizationAccountAccessRole', access_to_billing, credentials)
        print("********************************")
        print("Created acount: " + account_id)
        print("********************************")
    else:
        account_id = event['existing_accountid']
    
    print("Updating Shared Security account policy...")
    credentials = assume_role(event['securityaccount_id'], 'ST-S-Automation', None)
    update_policy(account_id, event['cloudtrail_bucket'], event['datadogcode_bucket'], credentials)
    print("********************************")
    
    print("Deploying resources from " + 'Member.yml' + " as " + 'Member' + " in " + 'us-east-1')
    mastercredentials = assume_role(event['masteraccount_id'], 'ST-S-Automation', None)
    credentials = assume_role(account_id, 'OrganizationAccountAccessRole', mastercredentials)
    template = get_template('Member.yml')
    stack = deploy_resources(template, 'Member', 'us-east-1', event['cloudtrail_bucket'], event['datadogcode_bucket'], event['securityaccount_id'], ddApiKey, credentials)
    print("********************************")
    print(stack)
    print("********************************")
    print("Resources deployed for account " + account_id)


def assume_role(account_id, account_role, credentials):

    if credentials is None:
       sts_client = boto3.client('sts')
    else:
	   sts_client = boto3.client('sts', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],)
       
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="NewRole")
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            print(e)
            time.sleep(10)
    return assumedRoleObject['Credentials']

def create_account(account_name, account_email, account_role, access_to_billing, credentials):

    '''
        Create a new AWS account and add it to an organization
    '''

    client = boto3.client('organizations', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],)
    try:
        create_account_response = client.create_account(Email=account_email, AccountName=account_name, RoleName=account_role, IamUserAccessToBilling=access_to_billing)
    except botocore.exceptions.ClientError as e:
        print(e)
        sys.exit(1)

    time.sleep(10)

    account_status = 'IN_PROGRESS'
    while account_status == 'IN_PROGRESS':
        create_account_status_response = client.describe_create_account_status(CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
        print("Create account status "+str(create_account_status_response))
        account_status = create_account_status_response.get('CreateAccountStatus').get('State')
    if account_status == 'SUCCEEDED':
        account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')
    elif account_status == 'FAILED':
        print("Account creation failed: " + create_account_status_response.get('CreateAccountStatus').get('FailureReason'))
        sys.exit(1)
    root_id = client.list_roots().get('Roots')[0].get('Id')

    return account_id

def update_policy(account_id, cloudtrail_bucket, datadogcode_bucket, credentials):

    s3 = boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],)
    iam = boto3.client('iam', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],)
	
    '''
	   Update CloudTrail bucket policy
    '''
    cloudtrail_arn = "arn:aws:s3:::" + cloudtrail_bucket +"/AWSLogs/" + account_id + "/*"
    cloudtrail_response = s3.get_bucket_policy(Bucket=cloudtrail_bucket)
    cloudtrailpolicy = json.loads(cloudtrail_response['Policy'])
    for cloudtrail_index in range(len(cloudtrailpolicy['Statement'])):
            if cloudtrailpolicy['Statement'][cloudtrail_index]['Sid'] == 'AWSCloudTrailWrite':
                folder_list = cloudtrailpolicy['Statement'][cloudtrail_index]['Resource']
                folder_list.append(cloudtrail_arn)
                cloudtrailpolicy['Statement'][cloudtrail_index]['Resource'] = folder_list 
    s3.put_bucket_policy(Bucket=cloudtrail_bucket, Policy=json.dumps(cloudtrailpolicy))

    '''
	   Update Datadog Lambda Code bucket policy
    '''
    newaccount_arn = "arn:aws:iam::" + account_id + ":root"
    datadog_response = s3.get_bucket_policy(Bucket=datadogcode_bucket)
    datadogcodepolicy = json.loads(datadog_response['Policy'])
    datadog_index = 0
    for statement in datadogcodepolicy['Statement']:
        if statement['Sid'] == 'CodeReadAccess':
            account_list = statement['Principal']['AWS']
            account_list.append(newaccount_arn)
            statement['Principal']['AWS'] = account_list
            datadogcodepolicy['Statement'][datadog_index] = statement
            datadog_index += 1
    s3.put_bucket_policy(Bucket=datadogcode_bucket, Policy=json.dumps(datadogcodepolicy))

    '''
	   Update LoggingLambdaRole role policy
    '''
    account_arn = "arn:aws:iam::" + account_id + ":role/ST-S-Automation"
    assumerole_response = iam.get_role_policy(RoleName='LoggingLambdaRole', PolicyName='AssumeRole')
    assumerole_policy = assumerole_response['PolicyDocument']
    for assumerole_index in range(len(assumerole_policy['Statement'])):
            if assumerole_policy['Statement'][assumerole_index]['Sid'] == 'AWSAssumeRole':
                account_list = assumerole_policy['Statement'][assumerole_index]['Resource']
                account_list.append(account_arn)
                assumerole_policy['Statement'][assumerole_index]['Resource'] = account_list
    iam.put_role_policy(RoleName='LoggingLambdaRole', PolicyName='AssumeRole', PolicyDocument=json.dumps(assumerole_policy))
	
    print("Policies successfully updated")

def get_template(template_file):

    '''
        Read a template file and return the contents
    '''

    print("Reading resources from " + template_file)
    f = open(template_file, "r")
    cf_template = f.read()
    return cf_template

def deploy_resources(template, stack_name, stack_region, cloudtrail_bucket, datadogcode_bucket, securityaccount_id, datadog_apikey, credentials):
    print(datadog_apikey)
    '''
        Create a CloudFormation stack of resources within the new account
    '''

    datestamp = time.strftime("%d/%m/%Y")
    client = boto3.client('cloudformation',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stack_region)
    print("Creating stack " + stack_name + " in " + stack_region)

    creating_stack = True
    while creating_stack is True:
        try:
            creating_stack = False
            create_stack_response = client.create_stack(
                StackName=stack_name,
                TemplateBody=template,
                Parameters=[
                    {
                        'ParameterKey' : 'cloudtrailbucket',
                        'ParameterValue' : cloudtrail_bucket
                    },
                    {
                        'ParameterKey' : 'securityaccountid',
                        'ParameterValue' : securityaccount_id
                    },
                    {
                        'ParameterKey' : 'Datadogbucket',
                        'ParameterValue' : datadogcode_bucket
                    },
                    {
                        'ParameterKey' : 'DatadogAPIToken',
                        'ParameterValue' : datadog_apikey
                    }
                ],
                NotificationARNs=[],
                Capabilities=[
                    'CAPABILITY_NAMED_IAM',
                ],
                OnFailure='ROLLBACK',
                Tags=[
                    {
                        'Key': 'ManagedResource',
                        'Value': 'True'
                    },
                    {
                        'Key': 'DeployDate',
                        'Value': datestamp
                    }
                ]
            )
        except botocore.exceptions.ClientError as e:
            creating_stack = True
            print(e)
            time.sleep(10)

    stack_building = True
    print("********************************")
    print("Stack creation in process...")
    print("********************************")
    print(create_stack_response)
    while stack_building is True:
        event_list = client.describe_stack_events(StackName=stack_name).get("StackEvents")
        stack_event = event_list[0]

        if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
           stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
            stack_building = False
            print("Stack construction complete.")
        elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
              stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
            stack_building = False
            print("Stack construction failed.")
            sys.exit(1)
        else:
            print(stack_event)
            print("********************************")
            print("Stack building . . .")
            print("********************************")
            time.sleep(10)

    stack = client.describe_stacks(StackName=stack_name)
    return stack