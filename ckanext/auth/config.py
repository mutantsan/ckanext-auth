from __future__ import annotations

import ckan.plugins.toolkit as tk

CONF_2FA_ENABLED = "ckanext.auth.2fa_enabled"
CONF_2FA_METHOD = "ckanext.auth.2fa_method"

METHOD_EMAIL = "email"
METHOD_AUTHENTICATOR = "authenticator"
ALLOWED_METHODS = [METHOD_EMAIL, METHOD_AUTHENTICATOR]


def is_2fa_enabled() -> bool:
    return tk.asbool(tk.config[CONF_2FA_ENABLED])


def get_2fa_method() -> str:
    return tk.config[CONF_2FA_METHOD]


def is_email_2fa_enabled() -> bool:
    return get_2fa_method() == METHOD_EMAIL


def is_totp_2fa_enabled() -> bool:
    return get_2fa_method() == METHOD_AUTHENTICATOR
