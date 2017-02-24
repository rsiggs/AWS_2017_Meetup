# get\_sts\_creds.py
## AWS CLI Credentials for MFA Accounts

With MFA enabled accounts, you need to generate session tokens (via STS) to use the AWS CLI tools. This can be cumbersome and difficult to maintain as a process. 

### Quickstart - Minimum Requirements
* install boto3 AND upgrade awscli to the latest version 
* download the script and make it executable 
* run the script with "--configure" to make credential stanzas in your aws credentials file (not your config file) to have the prefix "mfa_" 
 * remove any environment variables relating to credentials
 * remove any credentials from your config file
* run the script: "get_sts_creds.py -p \<env\> [\<env\>]" where \<env\> is the name of an evironment 
 * to manipulate a stanza "[default]", don't specify -p \<env\> at all.

### Requirements

- A POSIX Operating system.  Known to work on Mac OS X, Ubuntu, CentOS, RedHat Linux, Oracle Linux, Windows (7,8,10,and current Server systems)
- Python 2.7, 3.4 and 3.5 
- Python Libraries:
 - boto3
- AWS CLI
- CLI configured with '~/.aws/credentials'
 - mfa enabled profiles should have "mfa_" prepended to their names, the --configure switch detailed below.

#### Example ~/.aws/credentials file
## Setup can be accomplished via the --configure switch to the script.

Notice:  This script will *NOT* look in your ~/.aws/config file for credentials.  
Move them to your credentials file.
```
[mfa_<PROFILE>]
aws_access_key_id = <AWS_ACCESS_KEY_ID>
aws_secret_access_key = <AWS_SECRET_ACCESS_KEY>
```
If you have additional configuration options in your credentials file, they should 
be moved to your config file.

For example, in this credentials file:
```
[mfa_<PROFILE>]
aws_access_key_id = <AWS_ACCESS_KEY_ID>
aws_secret_access_key = <AWS_SECRET_ACCESS_KEY>
region = us-east-1
output = text
```
the region and output config parameters can be moved to your config file (~/.aws/config) like so:
```
[<PROFILE>]
region = us-east-1
output = text
```

### Script Download
This script can be retrieved by doing a "Save as..." of this link: 

Or using the following command:
```
wget 
```
Place the script anywhere in your $PATH then make it executable.
```
chmod +x /path/to/script/get_sts_creds.py
```
The script can be renamed to anything that suits your preference.  

Install/Upgrade boto3 with the following command:
```
sudo pip install --upgrade boto3 awscli
```
You can't install or upgrade boto3 without upgrading awscli because they share a 
dependency that will get upgraded and break older versions of awscli if one is installed.

Run the script with --configure once to prefix your stanza names:
```
/path/to/script --configure
```

### Usage
##### Profiles:
Profiles are specified in your credentials file. The script will only allow
you to enter the name of a profile that exists in your credentials, reference
it without the "mfa_" prefix.

For example, in your credentials file you have your key for the prod account:
```
[mfa_prd]
region_name = us-east-1
aws_access_key_id = AKIAIEXAMPLEYUDLWU5A
aws_secret_access_key = ExampleWhPxssCt8EYqH7rfUHRp446DiPyMuNMqD
```

Get your STS credentials with the command:
```
/path/to/script -p prd
```
Note that you specify "prd" *NOT* "mfa_prd".

Then you can use your aws command line using the profile "prd":
```
aws --profile prd s3 ls
```

##### Common usage:
To allow yourself to use an STS key after you have authenticated with your token 
by default, first get your temporal key with '-p dev', then copy it to your default 
profile with '-D dev'.  This can also be done at the same time by specifying 
'mfa -p dev -D dev'.

One common pattern is to auth and default in one iteration:

```
$ get_sts_creds.py -p dev prd -D dev
```

Later, to switch to prd as default:

```
$ get_sts_creds.py -D prd
```

#### Generate Session Credentials for a specific profile
```
$ get_sts_creds.py --token_codes 123456 -p prd
$ get_sts_creds.py -c 123456 -p dev
```

#### Results
The script will use the ~/.aws/credentials file for `mfa_<PROFILE>` and create a 
new profile named `<PROFILE>`.
```
[<PROFILE>]
aws_access_key_id = <AWS_ACCESS_KEY_ID>
aws_secret_access_key = <AWS_SECRET_ACCESS_KEY>
aws_session_token = <AWS_SESSION_TOKEN>
expiration = <Expiration>
```
These credentials will be automatically used by the AWS cli, boto, boto3, eclipse, 
the JAVA AWS API and many 
other AWS enabled software packages by specifying the profile name.


#### Omit the token_codes Arguments to be Prompted for Them.
You can give multiple values for profiles, you will be prompted for them in the
order you listed them:
```
$ get_sts_token.py --profiles prd dev
Enter the token_code for prd: 313010
Enter the token_code for dev: 204436
Writing session credentials for prd, dev to /Users/roger.siggs-rss/.aws/credentials
```

#### Manage [default] credentials
```
$ get_sts_creds.py -D prd
$ get_sts_creds.py -D mfa_dev
```

The -D option will copy the named section to either default or mfa_default.  
mfa_\<section\> will be copied to mfa_default so running the script with no options 
will prompt for \<section\>'s token and write the temporal token to default.  

\<section\> will be copied to [default] so only the ephemeral token is affected.

### Useful features to be aware of
* use: 'get_sts_creds.py --rotate-keys \<profile\> [\<profile\>]' to generate new API keys and update your credentials file
* use: 'get_sts_creds.py --shell-variables \<profile\>' to generate shell directives to set your credentials in your environment
* use: 'get_sts_creds.py -p dev prd -D dev' to authenticate against both dev and prod, then make your dev credentials the default for API calls.
* see: 'get_sts_creds.py --help' for additional details and functionality

#### Example of AWS CLI usage
```
$ aws iam list-roles --profile dev
```

## Links
- http://boto3.readthedocs.org/en/latest/reference/services/sts.html
