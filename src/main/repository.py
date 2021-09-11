import logging, boto3, json, urllib3, os
from urllib.parse import urlencode
from crhelper import CfnResource
from slack_noti import *

logging.getLogger().setLevel(logging.INFO)
helper = CfnResource(json_logging=False, log_level='DEBUG', boto_level='CRITICAL', sleep_on_delete=120)
ssm = boto3.client('ssm')

def get_bitbucket_access_token(key, secret):
    try:
        oauth2_url = 'https://bitbucket.org/site/oauth2/access_token'
        body = urlencode({'grant_type': 'client_credentials'})
        basic_auth = urllib3.make_headers(basic_auth=f'{key}:{secret}')['authorization']
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': basic_auth}
        resp = http.request('POST', oauth2_url, body=body, headers=headers)
        resp_data = json.loads(resp.data.decode('utf-8'))
        return resp_data['access_token']
    except Exception as err:
        raise Exception(f'Error while requesting access token: {err}')

try:
    BITBUCKET_WORKSPACE_ID = ssm.get_parameter(Name='/bitbucket/workspace')['Parameter']['Value']
    BITBUCKET_GROUP_PRIVILEGES_URL = f'https://api.bitbucket.org/1.0/group-privileges/{BITBUCKET_WORKSPACE_ID}'
    BITBUCKET_REPOSITORIES_URL = f'https://api.bitbucket.org/2.0/repositories/{BITBUCKET_WORKSPACE_ID}'
    
    http = urllib3.PoolManager()

    # # BASIC_AUTH
    # BITBUCKET_USER = ssm.get_parameter(Name='/bitbucket/username')['Parameter']['Value']
    # BITBUCKET_PASSWORD = ssm.get_parameter(Name='/bitbucket/password', WithDecryption=True)['Parameter']['Value']
    # BASIC_AUTH = urllib3.make_headers(basic_auth=f'{BITBUCKET_USER}:{BITBUCKET_PASSWORD}')['authorization']
    # HEADERS = {'Content-Type': 'application/json', 'Authorization': BASIC_AUTH}

    # BEARER
    BITBUCKET_OAUTH2_CONSUMER_KEY = ssm.get_parameter(Name='/bitbucket/oauth2-consumer/key')['Parameter']['Value']
    BITBUCKET_OAUTH2_CONSUMER_SECRET = ssm.get_parameter(Name='/bitbucket/oauth2-consumer/secret', WithDecryption=True)['Parameter']['Value']
    BEARER_TOKEN = get_bitbucket_access_token(BITBUCKET_OAUTH2_CONSUMER_KEY, BITBUCKET_OAUTH2_CONSUMER_SECRET)
    HEADERS = {'Content-Type': 'application/json', 'Authorization': f'Bearer {BEARER_TOKEN}'}
    ENABLE_SLACK_NOTI = os.environ['ENABLE_SLACK_NOTI']

except Exception as err:
    helper.init_failure(err)


def encode_physical_id(workspace_id, repo_name):
    return f'bitbucket_{workspace_id}_{repo_name}'

def decode_physical_id(physical_id):
    try: 
        items = physical_id.split('_')
        return {'git_hosting_service': items[0], 'workspace_id': items[1], 'repo_name': items[2]}
    except Exception as err:
        return 'invalid_bitbucket'


def validate_properties(properties, request_type, old_properties={}):
    supported_properties = ['ServiceToken', 'RepoName', 'Description', 'ProjectKey', 'Private', 'MainBranch', 'AdditionalBranches', 'DefaultReviewers', 'Privileges', 'BranchPermissionProfile']
    required_properties = ['ServiceToken', 'RepoName', 'ProjectKey']
    invalid_values = ('', None, [''], [])
    
    try: 
        # Validate required properties
        for p in required_properties:
            if p not in properties:
                raise Exception(f'Property {p} has not been defined.')

        # Validate supported properties and empty values for required properties
        for p in properties:
            if p not in supported_properties:
                raise Exception(f'Property {p} is not supported.')
            if properties[p] in invalid_values:
                if p not in required_properties: # This condition supports Service Catalog empty input params
                    continue
                raise Exception(f'Property {p} has invalid value {properties[p]}.')

        # Validate sub properties' invalid values
        for group_privilege in properties['Privileges']:
            for key in group_privilege: 
                if group_privilege[key] in invalid_values:
                    raise Exception(f"There's a {key} in Privileges has invalid value")

        return
    except Exception as err:
        raise Exception(f'Error validating template: {err}')


def create_update_repository(repo_name, request_type, properties):
    if request_type == 'Create': 
        method = 'POST'
    elif request_type == 'Update': 
        method = 'PUT'
    repo_url = f'{BITBUCKET_REPOSITORIES_URL}/{repo_name}'
    project_key = properties.get('ProjectKey')
    is_private = properties.get('Private', True)
    description = properties.get('Description', '')
    body = {
        'scm': 'git',
        'project': {
            'key': project_key
        },
        'is_private': is_private,
        'description': description
    }
    
    try: 
        logging.info('Creating/Updating Repo')
        resp = http.request(method, repo_url, body=json.dumps(body).encode('utf-8'), headers=HEADERS)
        resp_data = json.loads(resp.data.decode('utf-8'))
        if 'error' in resp_data:
            raise Exception(resp_data)
        
        # Make Outputs
        helper.Data['Name'] = repo_name
        helper.Data['Url'] = resp_data['links']['html']['href']
        helper.Data['Uuid'] = resp_data['uuid']
        helper.Data['CloneUrlHttp'] = resp_data['links']['clone'][0]['href']
        helper.Data['CloneUrlSsh'] = resp_data['links']['clone'][1]['href']
        
        logging.info('Repo created/updated')
        return
    except Exception as err:
        raise Exception(f'Error creating or updating repository: {err}')


# Create Main Branch (Update is not handled at the moment - BitBucket API doesn't support any API to change main branch at the moment. )
def create_main_branch(repo_name, properties):
    logging.info('Creating main branch')
    main_branch = properties.get('MainBranch', 'master')
    if main_branch == '': main_branch = 'master'  # Support for AWS Service Catalog empty value

    body = urlencode({'branch': main_branch, 'message': 'Initial Commit', 'author': 'BuildBot <build.bot@non-exist.com>'})
    url = f'{BITBUCKET_REPOSITORIES_URL}/{repo_name}/src'
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': f'Bearer {BEARER_TOKEN}'}
    
    try: 
        resp = http.request('POST', url, headers=headers, body=body)
        if resp.status != 201: 
            # Warning! Error response is in html format not json.
            raise Exception('Main branch failed to create.')
        else: 
            logging.info('Main branch created')
            return 
    except Exception as err: 
        raise Exception(f'Error creating main branch: {err}')

def get_initial_commit(repo_name):
    url = f'{BITBUCKET_REPOSITORIES_URL}/{repo_name}/commits'
    try: 
        resp = http.request('GET', url, headers=HEADERS)
        if resp.status >= 400:
            raise Exception('Error without specific message')
        else: 
            resp_data = json.loads(resp.data.decode('utf-8'))
            initial_commit_hash = resp_data['values'][0]['hash']
            logging.info(f'Initial Commit Hash is {initial_commit_hash}')
            return initial_commit_hash
    except Exception as err: 
        raise Exception(f'Error getting initial commit hash: {err}')

def create_branch(repo_name, branch_name, initial_commit_hash):
    url = f'{BITBUCKET_REPOSITORIES_URL}/{repo_name}/refs/branches'
    body = {'name': branch_name, 'target': {'hash': initial_commit_hash}}
    try: 
        resp = http.request('POST', url, body=json.dumps(body).encode('utf-8'), headers=HEADERS)
        resp_data = resp.data.decode('utf-8')
        if resp.status >= 400: 
            logging.info(f'Branch {branch_name} failed to create') 
            raise Exception(resp_data)
        else: 
            logging.info(f'Branch {branch_name} created')
            return 
    except Exception as err: 
        raise Exception(f'Error creating additional branch {branch_name}: {err}')

def create_branches(repo_name, properties):
    try: 
        branches = properties.get('AdditionalBranches', [''])
        if branches == ['']: # Support for AWS Service Catalog empty value
            return
        initial_commit_hash = get_initial_commit(repo_name)
        logging.info('Creating additional braches')
        for branch_name in branches: 
            create_branch(repo_name, branch_name, initial_commit_hash)
        logging.info('Additional branches created')
        return
    except Exception as err:
        raise Exception(f'Error creating branches: {err}')


# BitBucket Group Privileges Functions
def set_group_privilege(repo_name, method, group_owner, group_slug, privilege=''):
    try:
        group_privileges_url = f'{BITBUCKET_GROUP_PRIVILEGES_URL}/{repo_name}/{group_owner}/{group_slug}'
        if method == 'PUT': 
            headers = {'Content-Type': 'text/plain', 'Authorization': f'Bearer {BEARER_TOKEN}'} 
            resp = http.request(method, group_privileges_url, body=privilege.encode('utf-8'), headers=headers)
        elif method == 'DELETE':
            headers = {'Authorization': f'Bearer {BEARER_TOKEN}'}
            resp = http.request(method, group_privileges_url, headers=headers)
            
        resp_data = resp.data.decode('utf-8')
        if resp.status >= 400: 
            logging.info(f'Failed to configure privilege for {group_slug}.')
            raise Exception(resp_data)
        else: 
            logging.info(f'Privilege for group {group_slug} is set')
            return
    except Exception as err: 
        raise Exception(f'Error setting group privilege {group_slug}: {err}')

def set_group_privileges(repo_name, request_type, properties, old_properties={}):
    try: 
        if 'Privileges' not in properties and 'Privileges' not in old_properties:
            return

        group_privileges = properties.get('Privileges')
        
        if request_type == 'Update' and 'Privileges' in old_properties:
            logging.info('Checking and removing group privileges')
            new_group_list = []
            if group_privileges != None:
                for group_privilege in group_privileges:
                    new_group_list.append(group_privilege['GroupName'])
            for old_group_privilege in old_properties['Privileges']:
                if old_group_privilege['GroupName'] not in new_group_list:
                    set_group_privilege(repo_name, 'DELETE', old_group_privilege['GroupOwner'], old_group_privilege['GroupName'])
            
        if 'Privileges' in properties:
            logging.info('Adding group privileges')
            for group_privilege in group_privileges: 
                set_group_privilege(repo_name, 'PUT', group_privilege['GroupOwner'], group_privilege['GroupName'], group_privilege['Privilege'])
        
        logging.info('Group privileges all set')
        return 
    except Exception as err: 
        raise Exception(err)


# Define Default Reviewers
def set_default_reviewer(repo_name, method, default_reviewer):
    default_reviewer_url = f'{BITBUCKET_REPOSITORIES_URL}/{repo_name}/default-reviewers/{default_reviewer}'
    headers = {'Authorization': f'Bearer {BEARER_TOKEN}'}
    try: 
        resp = http.request(method, default_reviewer_url, headers=headers)
        resp_data = resp.data.decode('utf-8')
        if resp.status >= 400: 
            logging.info(f'Failed to set default reviewer {default_reviewer}.')
            raise Exception(resp_data)
        else: 
            return
    except Exception as err:
        raise Exception(f'Error while setting default reviewer {default_reviewer}: {err}')

def set_default_reviewers(repo_name, request_type, properties, old_properties={}): 
    try:
        if 'DefaultReviewers' not in properties and 'DefaultReviewers' not in old_properties:
            return
        
        if request_type == 'Update' and 'DefaultReviewers' in old_properties:
            logging.info('Checking and removing default reviewers')
            new_default_reviewer_list = properties.get('DefaultReviewers', [])
            for old_default_reviewer in old_properties['DefaultReviewers']:
                if old_default_reviewer not in new_default_reviewer_list:
                    set_default_reviewer(repo_name, 'DELETE', old_default_reviewer)

        if 'DefaultReviewers' in properties:
            logging.info('Setting default reviewers')
            for default_reviewer in properties['DefaultReviewers']:
                set_default_reviewer(repo_name, 'PUT', default_reviewer)

        logging.info('Default reviewers set')
        return
    except Exception as err:
        raise Exception(err)


# Set Branch Permissions
def set_branch_permissions(repo_name, request_type, properties):
    if 'BranchPermissionProfile' not in properties: 
        return
        
    main_branch = properties.get('MainBranch', 'master')
    if main_branch == '': main_branch = 'master' # Support for AWS Service Catalog empty value
    branch_restrictions = {
        "Default": [
            {'kind': 'require_approvals_to_merge', 'branch_match_kind': 'glob', 'pattern': main_branch, 'value': 1},
            {'kind': 'require_default_reviewer_approvals_to_merge', 'branch_match_kind': 'glob', 'pattern': main_branch, 'value': 1},
            {'kind': 'delete', 'branch_match_kind': 'glob', 'pattern': main_branch},
            # {
            #     'kind': 'push', 'branch_match_kind': 'glob', 'pattern': main_branch,
            #     'groups': [{"slug": "admin", "type": "group"},{"slug": "security-officers","type": "group"}]
            # }
        ]
    }
    branch_permission_profile = properties.get('BranchPermissionProfile', 'Default')
    branch_restrictions_url = f'https://api.bitbucket.org/2.0/repositories/{BITBUCKET_WORKSPACE_ID}/{repo_name}/branch-restrictions'

    try:
        logging.info('Setting branch permissions')
        for branch_restriction in branch_restrictions[branch_permission_profile]:
            resp = http.request('POST', branch_restrictions_url, body=json.dumps(branch_restriction).encode('utf-8'), headers=HEADERS)
            resp_data = resp.data.decode('utf-8')
            if resp.status != 201: 
                raise Exception(f'Error setting branch permission: {resp_data}')
        
        logging.info('Branch permissions are all set.')
        return 
    except Exception as err:
        raise Exception(err)


@helper.create
def create(event, context):
    try: 
        request_type = event['RequestType']
        properties = event['ResourceProperties']
        validate_properties(properties, request_type)

        repo_name = properties['RepoName']
        create_update_repository(repo_name, request_type, properties)
        create_main_branch(repo_name, properties)
        create_branches(repo_name, properties)
        set_group_privileges(repo_name, request_type, properties)
        set_default_reviewers(repo_name, request_type, properties)
        set_branch_permissions(repo_name, request_type, properties)

        logging.info('Repo created and related settings configured successfully')
        physical_id = encode_physical_id(BITBUCKET_WORKSPACE_ID, repo_name)

        if ENABLE_SLACK_NOTI == 'Yes': send_slack_message('success', event)
        return physical_id

    except Exception as err:
        if ENABLE_SLACK_NOTI == 'Yes': send_slack_message('failed', event, error_message=err)
        raise Exception(f'Error while creating stack: {err}')


@helper.update
def update(event, context):
    try:
        physical_id = event['PhysicalResourceId']
        request_type = event['RequestType']
        properties = event['ResourceProperties']
        old_properties = event['OldResourceProperties']
        repo_name = decode_physical_id(physical_id)['repo_name']
        new_repo_name = properties.get('RepoName')

        if new_repo_name != repo_name:
            event['RequestType'] = 'Create'
            return create(event, context)
        else: 
            validate_properties(properties, request_type, old_properties)
            create_update_repository(repo_name, request_type, properties)
            set_group_privileges(repo_name, request_type, properties, old_properties)
            set_default_reviewers(repo_name, request_type, properties, old_properties)
            return physical_id

    except Exception as err:
        raise Exception(f'Error while updating stack: {err}')


@helper.delete
def delete(event, context):
    try: 
        physical_id = event['PhysicalResourceId']
        decoded_physical_id = decode_physical_id(physical_id)
        if decoded_physical_id == 'invalid_bitbucket' or decoded_physical_id['git_hosting_service'] != 'bitbucket':
            return 

        repo_name = decoded_physical_id['repo_name']
        repo_url = f'{BITBUCKET_REPOSITORIES_URL}/{repo_name}'
        logging.info(f'Deleting Repo {repo_name}')
        resp = http.request('DELETE', repo_url, headers=HEADERS)
        if resp.status != 204: 
            resp_data = json.loads(resp.data.decode('utf-8'))
            raise Exception(resp_data)

    except Exception as err: 
        raise Exception(f'Error while deleting repo {repo_name}: {err}')


def handler(event, context):
    helper(event, context)
