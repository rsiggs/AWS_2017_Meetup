# aws_user -- Tool to create/update AWS IAM User objects in multiple accounts

## Overview

This is a command line tool for creating or updating an Amazon AWS IAM user.

* The command expects an email address.
* From an email address, the username is constructed.
 * If the AWS account is "dev" and the user email is
  "first.last@gmail.com the username becomes "first.last-dev".
  
* The existence of the username is verified. If the user does not exist, the account is created.

* Optionally AWS group(s) can be provided on the command line and the user
 will be added to them. Default IAM groups are always added the user, and configurable in aws_data

* A newly generated password is always assigned.
 * The user will receive an email containing the new password.
 * The user will be required to change their password upon first login.

* With the `--dry-run` option it will not create or update the user, but 
will say what it would do and provide error messages for any invalid inputs, 
like AWS groups that don't exist.

The email sent to the user contains:  
* Temporary password
* A URL for the AWS console is provided in the email.
* A link to the document on configuring an MFA device.
* The email is sent from an address configured in the script.

**NOTE: an email relay service listening on `localhost` is required on the
 host where you run this tool since it needs to send email. If no mailhost is available, or email is not desired, use the '--no-mail' option**

### Example of Email Sent to User

```
Your dev environment AWS login is ready. When you first login it will make you change your password.

   Username: roger.siggs-dev
   Password: GwE-!4we

MFA (multi-factor authentication) is required for all human accounts.
Please enable MFA as soon as possible. Instructions for setting up MFA:

  http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html

The AWS console URL where you can login, change your password and setup an MFA device is:

  https://<accountname_alias>.signin.aws.amazon.com/console

If you have any questions, please contact your administrator
```

## Amazon Permissions

Amazon access for the program comes from default credential resolution of the
AWS boto3 library: env, credentials file (default), instance profile. Alternate profiles are not currently supported.

Permission is required to call the AWS IAM service API's AcccountPasswordPolicy, create_user, User, LoginProfile.update,
create_login_profile, Group and User.add_group methods.


## Usage

```
$ aws_user -h
usage: aws_user [-h] --user-email USER_EMAIL [--groups [GROUPS [GROUPS ...]] |
                --mimic MIMIC | --change-password | --delete-mfa |
                --delete-user] [--dry-run]

Create or Update AWS Users

optional arguments:
  -h, --help            show this help message and exit
  --user-email USER_EMAIL, --email USER_EMAIL
                        The email of the user to add/update, username is
                        derived from this
  --groups [GROUPS [GROUPS ...]]
                        List of groups to add the user to
  --mimic MIMIC         Mimic the groups and managed polices of existing named
                        user, removes any current groups or policies
  --change-password     Change the password of an existing user and mail it to
                        them
  --delete-mfa          Delete the MFA device for the user
  --delete-user         Delete the user account, if you know what you are
                        doing
  --dry-run             Only print messages about what the script might do

Upon success the script emails the username and new password to the email
address
```

Example with specific groups list: 

`aws_user --user-email roger.testing@somecompany.com --groups S3FullControl ReadOnly Things`

Example with a user to mimic: 

`aws_user --user-email roger.testing@somecompany.com --mimic co.worker-prd`

## Local installation

Ideally this will run from an EC2 instance within the AWS environment where the account created will reside. However, this can be run in a local environment with the [default] AWS profile being changed to match the AWS account. 

### Requirements

- Python 3.X
- Python Libraries: boto3, aws-auth-helper, docopt, dotmap

### Installation

It is best to use a python virtual environment, but if you are root and the system has python3 you can install this package
in the system site-packages. It's not recommended though.
