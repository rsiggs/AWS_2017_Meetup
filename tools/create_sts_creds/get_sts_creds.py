#!/usr/bin/env python
from __future__ import print_function

import argparse
import os
import botocore

try:
    import boto3
except ImportError:
    raise SystemExit('This script requires the boto3 module, please install it.\n'
                     'run: python -m pip install --user boto3')

try:
    # python3 renames this module
    import ConfigParser as configparser

    class NoDefaultSafeConfigParser(configparser.SafeConfigParser):
        """Class to make the python2 version of ConfigParser work like python3"""
        def add_section(self, section):
            """Create a new section in the configuration.

            Raise DuplicateSectionError if a section by the specified name
            already exists.

            This implementation removes the check for hardcoded string "default"
            but otherwise is a copy of RawConfigParser.add_section
            """

            if section in self._sections:
                raise DuplicateSectionError(section)
            self._sections[section] = self._dict()

except ImportError:
    # Import of ConfigParser from stdlib has failed so
    # we are running in python3, import the renamed
    # module and create an alias for input() to be
    # compatible with both python versions
    import configparser
    NoDefaultSafeConfigParser = configparser.SafeConfigParser
    raw_input = input

configparser.DEFAULTSECT = 'xXxXInVaLiDsEcTiOnNaMeXxXx'


class NoMFAFound(Exception):
    pass


class ConvenienceConfigParser(NoDefaultSafeConfigParser):
    def __init__(self):
        self.filename = self.get_aws_cli_credential_file_path()
        self.write_required = False
        NoDefaultSafeConfigParser.__init__(self)

    def read(self):
        NoDefaultSafeConfigParser.read(self, self.filename)

    def write(self):
        if self.write_required:
            print("Writing credentials to {}".format(
                self.filename))
            with open(self.filename, 'w') as configfile:
                NoDefaultSafeConfigParser.write(self, configfile)

    @staticmethod
    def get_aws_cli_credential_file_path(
            aws_cli_credential_file='credentials',
            home_path=os.path.expanduser('~')):

        aws_cli_credential_file_path = os.path.join(
            home_path, '.aws', aws_cli_credential_file)
        return aws_cli_credential_file_path

    def check_section(self, profile):
        if not self.has_section(profile):
            raise SystemExit('[{}] is not in the AWS credentials file.\n'
                             'Please specify a profile with "-p"'.format(profile))

    def copy_stanza(self, from_name, to_name):
        if self.has_section(to_name):
            self.remove_section(to_name)

        self.add_section(to_name)

        for option, value in self.items(from_name):
            self.set(to_name, option, value)
        self.write_required = True

    def get_session(self, profile):
        aws_access_key_id = self.get(profile, 'aws_access_key_id')
        aws_secret_access_key = self.get(profile, 'aws_secret_access_key')
        if not profile.startswith('mfa_'):
            aws_session_token = self.get(profile, 'aws_session_token')
        else:
            aws_session_token = None

        session = boto3.session.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token)

        return session

    def get_client(self, profile, resource):
        return self.get_session(profile).client(resource)

    def get_mfa_serial_number(self, profile):
        iam = self.get_client(profile, 'iam')
        try:
            mfa = iam.list_mfa_devices()
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                raise SystemExit('You do not appear to have sufficient access to retrieve your MFA serial\n'
                                 'Please escalate this to your Administrator\n'
                                 'Error Code was: {}'.format(e.response['Error']['Code']))
            else:
                raise

        if 'MFADevices' not in mfa or not mfa['MFADevices']:
            raise NoMFAFound()

        return mfa['MFADevices'][0]['SerialNumber']

    def get_session_token(self, profile, token_code, duration):

        try:
            mfa_serial_number = self.get_mfa_serial_number(profile)
        except NoMFAFound:
            raise SystemExit('You do not appear to have any MFA devices configured'
                             ' for the profile {}'.format(profile))

        if not token_code:
            token_code = prompt_for_token_code(profile)

        return self.get_client(profile, 'sts').get_session_token(
            SerialNumber=mfa_serial_number,
            TokenCode=token_code,
            DurationSeconds=duration)['Credentials']

    def update_temporal(self, profile, credentials):
        # Check if profile already exists. If not, add section
        if not self.has_section(profile):
            self.add_section(profile)

        # Copy all the existing stuff (region_name, etc.) before we copy the STS creds
        self.copy_stanza('mfa_{}'.format(profile), profile)

        for key, value in (
                ('expiration', credentials['Expiration'].strftime('%c')),
                ('aws_access_key_id', credentials['AccessKeyId']),
                ('aws_secret_access_key', credentials['SecretAccessKey']),
                ('aws_session_token', credentials['SessionToken'])):
            self.set(profile, key, value)
        self.write_required = True

    def rotate_key(self, profile):
        profile_name = '{}'.format(profile)
        profile_init = 'mfa_{}'.format(profile)

        for section in (profile_name, profile_init):
            self.check_section(section)

        iam = self.get_client(profile, 'iam')
        current_key = self.get(profile_init, 'aws_access_key_id')
        try:
            response = iam.create_access_key()
            iam.delete_access_key(AccessKeyId=current_key)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'LimitExceeded':
                print()
                print('You already have two access keys on your {} account.'.format(profile_name))
                print()
                print('I can continue by deleting a current key and replacing it')
                print('but that is not as safe as if you had an open slot.')
                print()
                print('The alternative is to log into the console and delete a key.')
                user_input = raw_input('Do you want to proceed? ').strip().lower()[0]

                if user_input != 'y':
                    return

                try:
                    iam.delete_access_key(AccessKeyId=current_key)
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        print('Something is wrong in your credentials that I cannot fix')
                        return
                    else:
                        raise
                response = iam.create_access_key()
            elif e.response['Error']['Code'] == 'NoSuchEntity':
                pass
            elif e.response['Error']['Code'] == 'ExpiredToken':
                raise SystemExit("You need to authenticate using your MFA device\n"
                                 "before you can manipulate your API keys.")
            else:
                debug(e.response['Error'])
                raise SystemExit("The AWS API returned the following error: "
                                 "{}".format(e.response['Error']['Code']))

        self.set(profile_init, 'aws_access_key_id', response['AccessKey']['AccessKeyId'])
        self.set(profile_init, 'aws_secret_access_key', response['AccessKey']['SecretAccessKey'])
        self.write_required = True


args = None


def debug(x):
    if args.debug:
        print("DEBUG:", x)


def prompt_for_token_code(profile_name):
    while True:
        user_input = raw_input('Enter the token_code for {}: '.format(profile_name)).strip()
        if user_input:
            if len(user_input) != 6:
                print("token_codes are six digits")
                continue

            try:
                int(user_input)
            except ValueError:
                print("token_codes should be all digits")
                continue

            return user_input


def parse_commandline(configuration, largs=None):
    global args

    ALL_PROFILES = [section.split('_', 1)[1].lower()
                    for section in configuration.sections()
                    if section.startswith('mfa_')]
    STS_PROFILES = [section for section in ALL_PROFILES
                    if section.lower() != 'default']
    COMBINED_PROFILES = [section.lower() for section in configuration.sections()
                         if section.lower() not in ('default', 'mfa_default')]
    LCASE_PROFILES = {p.lower(): p for p in STS_PROFILES}

    parser = argparse.ArgumentParser(
        description='Manage session tokens in your ~/.aws/credentials file')

    action_group = parser.add_mutually_exclusive_group()

    action_group.add_argument(
        '--configure',
        action='store_true',
        help='Copy any non-temporal keys to a stanza prefixed with "mfa_"')

    action_group.add_argument(
        '--profiles', '-p',
        nargs='*',
        choices=STS_PROFILES,
        default=['default'],
        help='Sections of your credentials prefixed with "mfa_"')

    action_group.add_argument(
        '--rotate-keys', '-R',
        nargs='+',
        choices=ALL_PROFILES,
        help='Replace API key for profiles with newly created keys and update credentials file')

    action_group.add_argument(
        '--shell-variables',
        type=str,
        choices=STS_PROFILES,
        help='Output commands to set the token in your shell (bourne variants)')

    action_group.add_argument(
        '--docker-variables',
        type=str,
        choices=STS_PROFILES,
        help='Output a line suitable to set your credentials for a docker run command')

    duration_group = parser.add_mutually_exclusive_group()

    duration_group.add_argument(
        '--duration-seconds', '-d',
        type=int,
        default=43200,
        help='Duration of MFA token. Default is 43200 seconds (12 hours)')

    duration_group.add_argument(
        '--duration-hours', '-H',
        type=int,
        help='Duration of MFA token in hours.')

    parser.add_argument(
        '--token-codes', '-c',
        nargs='*',
        help='Current MFA Token code.  If not given, script will prompt for it.')

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Do everything except actually write the new credentials to disk')

    parser.add_argument(
        '--make-default', '-D',
        type=str,
        default=None,
        choices=COMBINED_PROFILES,
        help='Copy profile to be the default')

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debugging output')

    args = parser.parse_args(args)

    debug(args)

    if args.duration_hours:
        args.duration_seconds = args.duration_hours * 3600

    if args.duration_seconds > 129600:
        raise SystemExit("The maximum duration allowed by AWS is 36 hours (129600 seconds)")
    elif args.duration_seconds < 900:
        raise SystemExit("The minimum duration allowed by AWS is 900 seconds")

    if args.make_default:
        args.profiles = [a for a in args.profiles if a != 'default']

    if args.rotate_keys and 'default' in args.rotate_keys and len(STS_PROFILES):
        raise SystemExit('Refusing to rotate your default key unless it is your only key')

    debug(args)


def authenticate_profile(profile, token_code, configuration):
    profile_name = '{}'.format(profile)
    profile_init = 'mfa_{}'.format(profile)

    configuration.check_section(profile_init)

    for x in range(1, 3):
        try:
            sts_creds = configuration.get_session_token(profile_init,
                                                        token_code,
                                                        args.duration_seconds)
            break
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('Access Denied, check your token and try again...')
                token_code = None
            else:
                raise SystemExit("The AWS API returned the following error\n"
                                 "{}".format(e.response['Error']['Code']))
    else:
        print("Authentication for profile {} failed, moving on.\n".format(profile_name))
        return False

    if args.shell_variables:
        print('AWS_ACCESS_KEY_ID={}\n'
              'AWS_SECRET_ACCESS_KEY={}\n'
              'AWS_SESSION_TOKEN={}\n'
              'export AWS_ACCESS_KEY_ID AWS_ACCESS_SECRET_KEY '
              'AWS_SESSION_TOKEN'.format(sts_creds["AccessKeyId"],
                                         sts_creds["SecretAccessKey"],
                                         sts_creds["SessionToken"]))
    elif args.docker_variables:
        print(' -e AWS_ACCESS_KEY_ID={}'
              ' -e AWS_SECRET_ACCESS_KEY={}'
              ' -e AWS_SESSION_TOKEN={}'
              ''.format(sts_creds["AccessKeyId"],
                        sts_creds["SecretAccessKey"],
                        sts_creds["SessionToken"]))
    else:
        configuration.update_temporal(profile_name, sts_creds)


def main():
    # get AWS credentials from init profiles
    configuration = ConvenienceConfigParser()
    configuration.read()
    parse_commandline(configuration)

    if args.token_codes:
        if len(args.token_codes) != len(args.profiles):
            raise SystemExit('You have to give the same number of profiles and token_codes')
    else:
        args.token_codes = [None] * len(args.profiles)

    if args.configure:
        debug('configure')
        for section in configuration.sections():
            mfa_section = 'mfa_{}'.format(section)
            if not (section.startswith('mfa_')
                    or configuration.has_option(section, 'expiration')
                    or configuration.has_section(mfa_section)):
                print('Copying {} to {}'.format(section, mfa_section))
                configuration.copy_stanza(section, mfa_section)

    elif args.rotate_keys:
        debug('rotate')
        for profile in args.rotate_keys:
            print('Updating key in {}'.format(profile))
            configuration.rotate_key(profile)

    elif args.shell_variables or args.docker_variables:
        debug('shell vars')
        authenticate_profile(args.shell_variables or args.docker_variables,
                             args.token_codes[0] if args.token_codes else None,
                             configuration)
    else:
        debug('default action')
        for profile, token_code in zip(args.profiles, args.token_codes):
            authenticate_profile(profile,
                                 token_code,
                                 configuration)

        if args.make_default:
            if args.make_default.startswith('mfa_'):
                print("Making stanza '{}' the default MFA token".format(args.make_default))
                configuration.copy_stanza(args.make_default, 'mfa_default')
            else:
                print("Making stanza '{}' the default".format(args.make_default))
                configuration.copy_stanza(args.make_default, 'default')
            write_required = True

    if not args.dry_run:
        configuration.write()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting on keyboard interrupt")
