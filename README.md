# BitBucket CloudFormation Custom Resource

This project enables the use of a custom resource in CloudFormation that provisions repositories in Bitbucket Cloud.

`crhelper` lib has been used to simplify communication with CloudFormation.


## Requirements

The following SSM Parameters must be available and have valid values (These are recommended only. You can hard-code these values in `src/main/reponsitory.py` file as well)

- `/bitbucket/workspace`: Your BitBucket Workspace ID
- `/bitbucket/oauth2-consumer/key`: Your BitBucket OAuth Key
- `/bitbucket/oauth2-consumer/secret`: Your BitBucket OAuth Secret

### Create BitBucket OAuth Consumer Key

- To further improve security when calling API from BitBucket, a pair of OAuth Consumer Key and Secret is used to get Bearer access token. Though in any case requires, **BASIC-AUTH code in the function can be uncommented and used instead**. (Also adjust a few `Authorization` header accordingly within the function)

1. Access your **BitBucket Workspace** using *admin* privilege
2. Go to your Workspace **Settings** > **Apps and Features** > **OAuth consumers**
3. Click **Add Consumer**
   - **Name**: BitBucket Custom Resource
   - **Callback URL**: Just type a dummy url here. e.g. 'example.com'
   - **Permissions** (You can allow all the left hand side permissions first then adjust later to test)
     - Account: **Read**
     - Workspace Membership: **Write**
     - Projects: **Read**
     - Repositories: **Write**, **Admin**, **Delete**
4. Grab the key and secret then put them to SSM Parameter Store subsequently with names `/bitbucket/oauth2-consumer/key` and `/bitbucket/oauth2-consumer/secret`

---

## Provision Custom Resource

Have a look at the `template.yml`. This template will install a Lambda Function that is used to process the CloudFormation BitBucket Custom Resource `Custom::BitBucketRepository`. No BitBucket repository will be created. 

By default, Slack Notification is disabled because it requires some configurations. Please check [Slack Notification](##extra-slack-notification) section. 

1. **Install SAM CLI**: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html <- Very easy
   ```sh
   $ sam --version
   ```
1. Edit serverless artifact bucket in `deploy.sh` script. SAM will zip function code and put it to S3. 
   ```sh
   ARTIFACT_BUCKET='your-artifact-bucket-name'
   ```
1. Run the script. Make sure you have enough privileges.
   ```sh
   bash deploy.sh
   ```


---

## Template Declaration

BitBucket Repo CFN template will be used as the following: 

```yaml
AWSTemplateFormatVersion: "2010-09-09"

Resources:
  Repo:
    Type: Custom::BitBucketRepository
    Properties:
      ServiceToken: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::Region}:function:bitbucket-repo-custom-resource' # Created from template.yml
      RepoName: 'test-repo'
      ProjectKey: 'TEST'
      Description: Bitbucket Custom Resource Test
      Private: True
      MainBranch: 'master'
      AdditionalBranches: ['develop', 'release']
      DefaultReviewers: ['luong-quang-it', 'quangluong1993']
      Privileges: 
        - GroupOwner: luongquangit
          GroupName: security-officers
          Privilege: admin
        - GroupOwner: luongquangit
          GroupName: my-team
          Privilege: write
      BranchPermissionProfile: Default

Outputs:
  RepoName:
    Description: 'Repo Name'
    Value: !GetAtt Repo.Name
  RepoUuid:
    Description: 'Repo UUID'
    Value: !GetAtt Repo.Uuid
  RepoUrl:
    Description: 'Repo URL'
    Value: !GetAtt Repo.Url
  RepoCloneUrl: 
    Description: 'Repo Clone URL'
    Value: !GetAtt Repo.CloneUrlHttp
  RepoCloneSsh: 
    Description: 'Repo Clone SSH'
    Value: !GetAtt Repo.CloneUrlSsh
```

### Properties 

`RepoName` 

- Name of the Repository
- *Required*: Yes

`ProjectKey`

- Project *Key* of the Repository
- *Required*: Yes

`Description`

- Description of the Repo
- *Required*: No

`Private`

- `True` for *private* repo. `False` for *public* repo.
- *Required*: No
- *Default*: True

`MainBranch`

- Main Branch of the Repo. This branch will also be applied the pre-defined branch permission. 
- **Note**: This property is not Updatable and can only be used when first provisioning the stack only. Because BitBucket doesn't provide an API to set main branch. We can't update it afterward.
- *Required*: No
- *Default*: `master`

`AdditionalBranches`

- Additional Branch(es) for the Repo. 
- **Note**: This property is not Updatable. Use it when first provisioning the stack only.
- *Required*: No

`DefaultReviewers`

- Define default reviewers for the Repo. 
- *Required*: No

`Privileges`

- Define Group Privileges for the Repo. `GroupOwner`, `GroupName` and `Privilege` are all required for each specified entry.
  - `GroupOwner`: Workspace Name or UUID of the Group
  - `GroupName`: Group Name or UUID
  - `Privilege`: `read`, `write` or `admin`
- *Required*: No
  
`BranchPermissionProfile`

- This is actually a lazy approach to define branch permissions (or restrictions). Due to time constraint I can only hard code the **pre-defined branch permission rules as a "Profile"**. We only have 1 profile as of this writing:
  - `Default`
    - Prevent deleting main branch
    - Require **1** Assigned Reviewer approval to merge
    - Require **1** Default Reviewer approval to merge
- *Required*: No

---

## (Extra) Slack Notification

You can enable Slack Notifications to be informed of the repositories status provisioned via this BitBucket Custom Resource. 

Currently, only simple BitBucket **repo create status** notifications are supported. 

To enable, make sure the below are configured:

1. Set SSM Parameter name that contains Slack Webhook URL (Full URL) to `src/main/slack_noti.py`
   
   ```py
   SLACK_WEBHOOK_URL = ssm.get_parameter(Name='/input/ssm/param/name/here', WithDecryption=True)['Parameter']['Value']
   ```

2. In Lambda Function Environemnt Variable, Set `ENABLE_SLACK_NOTI` to `Yes`
   
   ```yml
   Resources:
    BitbucketRepositoryFunction:
      Type: AWS::Serverless::Function
      Properties:
        ...
        Environment:
          Variables:
            ENABLE_SLACK_NOTI: 'Yes'
   ```

Slack Notification by default will include CloudFormation Link, Repo Name, Repo Group Owner, and Repo URL. 

**Note**: Repo deletion notification is not supported at this writing. 

---

## References:

- https://support.atlassian.com/bitbucket-cloud/docs/group-privileges-endpoint/
- https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Bworkspace%7D/%7Brepo_slug%7D
- https://aws.amazon.com/blogs/infrastructure-and-automation/aws-cloudformation-custom-resource-creation-with-python-aws-lambda-and-crhelper/
- https://pypi.org/project/crhelper/