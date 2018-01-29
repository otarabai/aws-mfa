# aws-mfa

Authenticate AWS CLI with MFA device.

## Setup

You need python 2.7 running on your machine. For convenience, you can create
an alias in your `.bashrc` to the authentication script, to do that run the
following inside this directory:

```bash
echo "alias awsmfa='python $PWD/awsmfa.py'" >> ~/.bashrc
source ~/.bashrc
```

## Usage

Run `awsmfa` for the first time and follow the instructions toconfigure your
AWS account(s). Later you can add new AWS accounts by running
`awsmfa --configure` or `awsmfa -c`.

To authenticate, simply run `awsmfa` and follow the instructions.
For non-interactive authentication, use
`awsmfa -a <account-name> <mfa-code>` or just `awsmfa <mfa-code>` if you have
only one AWS account configured.

## TODO

- [ ] Support py3
- [ ] Support switching between already authenticated accounts
