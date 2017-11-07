#!/usr/bin/python
""" Authenticate with AWS using MFA device for AWS CLI usage """

import argparse
import ConfigParser
import hashlib
import os
import subprocess

CONFIG_PATH = os.path.expanduser('~/.aws/mfa-config')
CREDS_PATH = os.path.expanduser('~/.aws/credentials')

ConfigParser.DEFAULTSECT = 'default'

# pylint:disable=missing-docstring


def main():
    args = get_args()
    config = get_config()
    if not config or args.configure:
        config = create_or_update_config(config=config)
    account = args.account or pick_account(args, config)
    credentials = get_credentials(config, account, mfa_code=args.mfa_code)
    write_credentials(config, *credentials)


def get_args():
    parser = argparse.ArgumentParser(
        description="Authenticate with AWS CLI using MFA"
    )
    parser.add_argument('-c', '--configure', help="Run configuration wizard",
                        action='store_true')
    parser.add_argument('-a', '--account',
                        help="Account name to authenticate against")
    parser.add_argument('mfa_code', nargs='?')
    return parser.parse_args()


def get_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    config = ConfigParser.RawConfigParser()
    config.read(CONFIG_PATH)
    if not config.sections():
        return None
    return config


def create_or_update_config(config=None):
    config = config or ConfigParser.RawConfigParser()
    print "Configuring AWS account MFA:\n"
    while True:
        name = mandatory_input("Pick a name for this AWS account: ")
        config.add_section(name)
        config.set(name, 'aws_access_key_id',
                   mandatory_input("Access key ID: "))
        config.set(name, 'aws_secret_access_key',
                   mandatory_input("Secret access key: "))
        config.set(name, 'mfa_device_arn',
                   mandatory_input("MFA device ARN: "))
        more = mandatory_input(
            "Do you want to add another AWS account [y/n]: ")
        if more.strip() != 'y':
            break
    with open(CONFIG_PATH, 'wb') as config_file:
        config.write(config_file)
    print ("\nConfiguration has been saved to `%s`, you can update it directly"
           " or run `python %s --configure` to add new AWS accounts"
           % (CONFIG_PATH, os.path.basename(__file__)))
    return config


def pick_account(args, config):
    """
    Prompt the user to choose an AWS account if more than one is configured.
    """
    accounts = config.sections()
    if len(accounts) == 1:
        return accounts[0]
    for idx, account in enumerate(accounts):
        print "%d\t%s" % (idx, account)
    while True:
        choice_str = raw_input(
            "Pick an account number to authenticate with [0]: "
        ) or '0'
        try:
            choice = int(choice_str)
            assert choice < len(accounts)
        except:  # pylint:disable=bare-except
            print "Invalid choice"
            continue
        return accounts[choice]


def get_credentials(config, account, mfa_code=None, duration=86400):
    """
    Prompt the user for MFA code (if not supplied as argument) and use it to
    create and return a tuple of
    (access_key_id, secret_access_key, session_token).
    """
    print "Authenticating for account `%s`" % account
    access_key_id = config.get(account, 'aws_access_key_id')
    secret_access_key = config.get(account, 'aws_secret_access_key')
    mfa_device_arn = config.get(account, 'mfa_device_arn')
    while True:
        try:
            mfa_code = mfa_code or mandatory_input("MFA Code: ")
            credentials = subprocess.check_output(' '.join([
                "AWS_ACCESS_KEY_ID=%s" % access_key_id,
                "AWS_SECRET_ACCESS_KEY=%s" % secret_access_key,
                "aws sts get-session-token",
                "--duration %d" % duration,
                "--serial-number %s" % mfa_device_arn,
                "--token-code %s" % mfa_code,
                "--output text",
            ]), shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            print exc.output
            print "Authenticate error, please try again."
            mfa_code = None
            continue
        cred_parts = credentials.split()
        return (cred_parts[1], cred_parts[3], cred_parts[4])


def write_credentials(config, access_key_id, secret_access_key, session_token):
    """ Write credentials to ~/.aws/credentials """
    if is_credentials_file_dirty(config):
        confirm = mandatory_input(
            "The current credentials file `%s` was not created by this script"
            " or has been altered.\n"
            "Are you sure you want to overwrite it? [y/n] " % CREDS_PATH
        )
        if confirm.strip() != 'y':
            print 'Aborting!'
            return

    creds_config = ConfigParser.RawConfigParser()
    creds_config.set('default', 'aws_access_key_id', access_key_id)
    creds_config.set('default', 'aws_secret_access_key', secret_access_key)
    creds_config.set('default', 'aws_session_token', session_token)
    with open(CREDS_PATH, 'wb') as creds_file:
        creds_config.write(creds_file)

    creds_file_hash = get_credentials_file_hash()
    config.set('default', 'credentials_file_hash', creds_file_hash)
    with open(CONFIG_PATH, 'wb') as config_file:
        config.write(config_file)
    print "Credentials written successfully to `%s`." % CREDS_PATH


def is_credentials_file_dirty(config):
    """
    Check if the current credentials file is written by us.
    This is to make sure we don't overwrite user's credentials.
    """
    if not os.path.exists(CREDS_PATH):
        return False
    if not config.has_option('default', 'credentials_file_hash'):
        return True
    creds_file_hash = get_credentials_file_hash()
    return creds_file_hash != config.get('default', 'credentials_file_hash')


def get_credentials_file_hash():
    with open(CREDS_PATH) as creds_file:
        md5 = hashlib.md5(creds_file.read())
    return md5.hexdigest()


def mandatory_input(prompt):
    val = ''
    while not val.strip():
        val = raw_input(prompt)
    return val


if __name__ == '__main__':
    main()
