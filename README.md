[![Tests](https://github.com//ckanext-auth/workflows/Tests/badge.svg?branch=main)](https://github.com//ckanext-auth/actions)

# ckanext-auth

This extension partially based on the [ckanext-security](https://github.com/data-govt-nz/ckanext-security)

This extension provides a 2FA authentication mechanism for CKAN.

There are two methods of 2FA available:
- TOTP (Time-based One-Time Password) with authenticator apps like Google Authenticator, Authy, etc.
- Email


## Requirements

This extension uses Redis, so it must be configured for CKAN.

Compatibility with core CKAN versions:

| CKAN version    | Compatible?   |
| --------------- | ------------- |
| 2.9 and earlier | no            |
| 2.10+           | yes           |


## Installation

To install ckanext-auth:

1. Activate your CKAN virtual environment, for example:

     . /usr/lib/ckan/default/bin/activate

2. Clone the source and install it on the virtualenv

    git clone https://github.com//ckanext-auth.git
    cd ckanext-auth
    pip install -e .
	pip install -r requirements.txt

3. Add `auth` to the `ckan.plugins` setting in your CKAN
   config file (by default the config file is located at
   `/etc/ckan/default/ckan.ini`).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu:

     sudo service apache2 reload


## Config settings

There are several configuration settings available for this extension:

      - key: ckanext.auth.2fa_enabled
        default: true
        description: Enable two-factor authentication for users

      - key: ckanext.auth.2fa_method
        default: email
        description: The method to use for two-factor authentication. Options are `email` or `totp`.

      - key: ckanext.auth.2fa_email_interval
        default: 600
        description: TTL for the authentication code sent via email in seconds. Default is 10 minutes.

      - key: ckanext.auth.2fa_login_timeout
        default: 900
        description: Login timeout in seconds after N failed attempted. Default is 15 minutes.

      - key: ckanext.auth.2fa_login_max_attempts
        default: 10
        description: Number of failed login attempts before the login timeout is triggered.


## Tests

To run the tests, do:

    pytest --ckan-ini=test.ini


## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
