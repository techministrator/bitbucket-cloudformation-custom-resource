import urllib3, json, boto3, datetime
import botocore.exceptions

ssm = boto3.client('ssm')
http = urllib3.PoolManager()

BITBUCKET_WORKSPACE_ID = ssm.get_parameter(Name='/bitbucket/workspace')['Parameter']['Value']
SLACK_WEBHOOK_URL = ssm.get_parameter(Name='/slack/bitbucket-administration/webhook-url', WithDecryption=True)['Parameter']['Value']

message_template = {
  'success': {
    'icon': ':white_check_mark:',
    'message': 'REPOSITORY CREATE SUCCESS',
    'attachment': {
      "color": "#36a64f",
      "title": "CloudFormation Detail Link",
      "title_link": "",
      "text": "Provisioned via BitBucket Repo Toolkit",
      "fields": [],
      "footer": "BitBucket Custom Resource",
      "footer_icon": "https://res.cloudinary.com/apideck/icons/bitbucket",
    }
  },
  'failed': {
    'icon': ':x:',
    'message': 'REPOSITORY CREATE FAILED',
    'attachment': {
      "color": "#ff0000",
      "title": "CloudFormation Detail Link",
      "title_link": "",
      "text": "Provisioned via BitBucket Repo Toolkit",
      "fields": [],
      "footer": "BitBucket Custom Resource",
      "footer_icon": "https://res.cloudinary.com/apideck/icons/bitbucket",
    }
  }
}

def make_slack_message(status, event, error_message=None):
  try: 
    epoch_now_time = datetime.datetime.now().strftime('%s')
    region = event['StackId'].split(':')[3]
    repo_name = event['ResourceProperties'].get('RepoName', 'N/A')
    privileges = event['ResourceProperties'].get('Privileges', [])
    group_owner = privileges[0].get('GroupName', 'N/A')
    cfn_arn = event['StackId']
    cfn_link = f'https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/stackinfo?stackId={cfn_arn}'

    message_template[status]['attachment'].update({
      "title_link": cfn_link, 
      "fields": [
        {"title": "Repo Name", "value": repo_name, "short": True},
        {"title": "Group Owner", "value": group_owner, "short": True}
      ],
      "ts": epoch_now_time
    })
    
    if error_message != None: 
      message_template[status]['attachment']['fields'].append(
        {"title": "Error Message", "value": str(error_message), "short": True}
      )
    else:
      message_template[status]['attachment']['fields'].append(
        {"title": "Repo Link", "value": f'https://bitbucket.org/{BITBUCKET_WORKSPACE_ID}/{repo_name}', "short": True}
      )
    
    message = {
      'text': f"{message_template[status]['icon']} {message_template[status]['message']}",
      'attachments': [message_template[status]['attachment']]
    }
    return message
  except Exception as err:
    print(err)

def send_slack_message(status, event, error_message=None):
  try:
    slack_message = make_slack_message(status, event, error_message)
    encoded_slack_message = json.dumps(slack_message).encode('utf-8')
    resp = http.request('POST', SLACK_WEBHOOK_URL, body=encoded_slack_message, headers={'Content-Type': 'application/json'})
    print(str(resp.status) + " " + str(resp.data))
  except Exception as err:
    print(err)