#!/usr/bin/env python

"""Create/Update AWS User.
The user name is parsed from the email address.
If the user does not exist it is created.
The password is reset to a newly generated one.
When they login the user is forced to change their password.
If groups are provided it adds the user to them.
Upon success it emails the username and password to the AWS user.
"""

import re
import sys
import smtplib
from textwrap import dedent
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

from awsauthhelper import password
import boto3
from botocore.exceptions import ClientError
from aws_data import account_info

args = None

message_body_template_created = dedent('''\
        Your {} environment AWS login is ready. When you first login it will make you change your password.

            Username: {}
            Password: {}

        MFA (multi-factor authentication) is required for all human accounts.
        Please enable MFA as soon as possible. Instructions for setting up MFA:

           http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html

        The AWS console URL where you can login, change your password and setup an MFA device is:

           {}

        If you have any questions, please contact your Administrator ''')

message_body_template_password = dedent('''\
        Your {} environment AWS login password has been reset.

            Username: {}
            Password: {}

        MFA (multi-factor authentication) is required for all human accounts.
        Please enable MFA before close of business if you have not already.

           http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html

        The AWS console URL where you can login, change your password and setup an MFA device is:

           {}

        If you have any questions, please contact your Administrator''')

class User:
    EMAIL_ADDRESS_REGEX = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

    def __init__(self, user_email, account_name, dry_run):
        if account_name not in account_info:
            raise SystemExit('ERROR: Account: {} does not exist in '
                             '"account_info"'.format(account_name))

        self.dry_run = dry_run
        self.user_email = user_email
        self.account_name = account_name
        self.account = account_info[account_name]
        self.user_name = self.user_from_email(user_email)
        self.iam = boto3.resource('iam')
        self.get_user()

    def check_email_format(self, user_email):
        if not re.match(self.EMAIL_ADDRESS_REGEX, user_email):
            raise SystemExit('User email address looks bad: {}'.format(user_email))

    def user_from_email(self, user_email):
        self.check_email_format(user_email)
        return user_email.split('@')[0] + '-' + self.account.env

    def generate_password(self):
        password_policy = self.iam.AccountPasswordPolicy()
        new_password = password.generate(password_policy)
        return new_password

    @property
    def exists(self):
        try:
            user = self.iam.User(self.user_name)
            user.load()
            debug('Found user', user.name)
            return True
        except ClientError as ce:
            if ce.response['Error']['Code'] == 'NoSuchEntity':
                return False
            else:
                raise

    def get_user(self, create=False):
        if not create and not self.exists:
            return
        try:
            if not self.dry_run:
                self.user = self.iam.create_user(UserName=self.user_name)
            else:
                print('dry-run: would create Username: {}, in account: {}'
                      ''.format(self.user_name, self.account_name))
                self.user = self.iam.User(self.user_name)
        except ClientError as ce:
            if ce.response['Error']['Code'] == 'EntityAlreadyExists':
                self.user = self.iam.User(self.user_name)
            else:
                raise

    def set_login_profile(self, password=None):
        if not password:
            self.new_password = self.generate_password()
        else:
            self.new_password = password

        if not self.exists:
            raise SystemExit('ERROR: user {} does not exist'.format(self.user_name, ce))

        if not self.dry_run:
            try:
                login_profile = self.iam.LoginProfile(self.user_name)
                login_profile.update(Password=self.new_password, PasswordResetRequired=True)
            except ClientError as ce:
                if ce.response['Error']['Code'] == 'NoSuchEntity':
                    # A disabled account will not have a login profile to update so create one.
                    self.user.create_login_profile(Password=self.new_password, PasswordResetRequired=True)
                else:
                    raise 
        else:
            print('dry-run: would set login profile for: {} with new '
                  'password: {}'.format(self.user_name, self.new_password))

    def start_fresh(self):
        for group in self.user.groups.all():
            self.user.remove_group(GroupName=group.name)

        for policy in self.user.attached_policies.all():
            self.user.detach_policy(PolicyArn=policy.arn)

    def add_to_groups(self, groups, mimic):
        mimic_groups, mimic_policies = self.get_mimicked_entities(mimic)
        groups = set(groups)

        if mimic:
            self.start_fresh()

        try:
            for group in set(self.account.iam_default_groups) | groups | mimic_groups:
                if self.is_groupname_valid(group):
                    if not self.dry_run:
                        # idempotent
                        self.user.add_group(GroupName=group)
                    else:
                        print('dry-run: would add user: {} to group: {}'.format(self.user_name, group))
                else:
                    print(
                        "WARNING: {} not added to group: {} because it doesn't exist".format(
                            self.user_name, group),
                        file=sys.stderr)
        except ClientError as ce:
            raise SystemExit('ERROR: User: {} created/updated, but adding group membership '
                             'failed with: {}'.format(self.user_name, ce))

    def attach_policies(self, mimic):
        mimic_groups, mimic_policies = self.get_mimicked_entities(mimic)

        try:
            for policy in mimic_policies:
                if not self.dry_run:
                    self.user.attach_policy(PolicyArn=policy)
                else:
                    print('dry-run: would add policy: {} to user: {}'.format(policy, self.user_name))

        except ClientError as ce:
            raise SystemExit('ERROR: User: {} created/updated, but adding policies failed '
                             'with: {}'.format(self.user_name, ce))

    def new_user(self, mimic, groups=set()):
        self.get_user(create=True)
        self.set_login_profile()
        self.add_to_groups(groups, mimic)
        self.attach_policies(mimic)

    def update_user(self, mimic, groups=set()):
        self.add_to_groups(groups, mimic)
        self.attach_policies(mimic)

    def delete_mfa(self):
        for mfa in self.user.mfa_devices.all():
            mfa.disassociate()
            self.iam.VirtualMfaDevice(mfa.serial_number).delete()

    def delete_access_keys(self):
        for key in self.user.access_keys.all():
            key.delete()

    def delete_user(self):
        self.start_fresh()
        self.delete_access_keys()
        self.delete_mfa()
        try:
            self.user.LoginProfile().delete()
        except:
            pass
        self.user.delete()

    def is_groupname_valid(self, groupname):
        group_resource = self.iam.Group(groupname)
        try:
            _ = group_resource.group_id
            return True
        except ClientError as e:
            return False

    def get_mimicked_entities(self, username):
        if not username:
            return set(), set()

        try:
            user = self.iam.User(username)
            groups = set(group.name for group in user.groups.all())
            policies = (policy.arn for policy in user.attached_policies.all())
        except ClientError as ce:
            if ce.response['Error']['Code'] == 'NoSuchEntity':
                raise SystemExit('User to mimic {} does not exist'.format(username))
            else:
                raise

        return groups, policies

def debug(*message):
    global args

    if args.debug:
        print('DEBUG: {}'.format(" ".join(message)))

def send_email(user, template, dry_run):
    if args.no_email:
        return

    message_body = template.format(
        user.account.env,
        user.user_name,
        user.new_password,
        user.account.url)

    try:
        if not dry_run:
            send_user_email(user.user_email, message_body)
            print('{} account info sent to: {}'.format(user.user_name, user.user_email))
        else:
            print('dry-run: would send following email to: {}\n\n{}'.format(user.user_email, message_body))
    except Exception as e:
        print(e)
        print('\nFailed to send user email. This is what it tried to send:\n')
        print('{}\n'.format(message_body))

def send_user_email(
    send_to,
    msg_body,
    send_from='<service_or_group@email.address>',
    subject='AWS login info',
    server='localhost'):

    if not isinstance(send_to, list):
        send_to = [send_to]

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(msg_body))

    smtp = smtplib.SMTP(server)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()

def parse_commandline():
    from argparse import ArgumentParser, SUPPRESS

    parser = ArgumentParser(description="Create or Update AWS Users",
                            epilog="Upon success the script emails the username "
                            "and new password to the email address")

    parser.add_argument('--user-email', '--email',
                        dest='user_email',
                        required=True,
                        type=str,
                        help='The email of the user to add/update, username is derived from this')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--groups',
                       nargs='*',
                       default=[],
                       type=str,
                       help='List of groups to add the user to')
    group.add_argument('--mimic',
                       type=str,
                       help='Mimic the groups and managed polices of existing named user, '
                       'removes any current groups or policies')
    group.add_argument('--change-password',
                       action='store_true',
                       help='Change the password of an existing user and mail it to them')
    group.add_argument('--delete-mfa',
                       action='store_true',
                       help='Delete the MFA device for the user')
    group.add_argument('--delete-user',
                       action='store_true',
                       help='Delete the user account, if you know what you are doing')

    parser.add_argument('--i-know-what-im-doing',
                       action='store_true',
                       help=SUPPRESS)
    parser.add_argument('--debug',
                       action='store_true',
                       help=SUPPRESS)
    parser.add_argument('--no-mail',
                        action='store_true',
                        help='Do not send email to the user.')
    parser.add_argument('--dry-run',
                        action='store_true',
                        help='Only print messages about what the script might do')

    return parser.parse_args()

def account_alias():
    return boto3.client('iam').list_account_aliases()['AccountAliases'][0]

def run():
    global args

    args = parse_commandline()

    account_name = account_alias()
    user = User(args.user_email,
                account_name,
                args.dry_run)

    if user.exists:
        if args.change_password:
            print('changing password for user')
            user.set_login_profile()
            send_email(user, message_body_template_password, args.dry_run)
        elif args.delete_mfa:
            print('deleting mfa for user')
            user.delete_mfa()
        elif args.delete_user:
            if not user.exists:
                raise SystemExit('user does not exist')
            if args.i_know_what_im_doing:
                print('deleting user')
                user.delete_user()
            else:
                raise SystemExit('You don\'t know what you are doing')
        elif args.groups or args.mimic:
            print('updating groups for user {}'.format(user.user_name))
            user.update_user(args.mimic, args.groups)
        else:
            print('user exists but no change option was given')
    else:
        print('creating user')
        user.new_user(args.mimic, args.groups)
        send_email(user, message_body_template_created, args.dry_run)

if __name__ == '__main__':
    run()
