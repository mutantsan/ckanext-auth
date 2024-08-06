from __future__ import annotations

from ckan import types
from ckan.logic.schema import validator_args

from ckanext.auth import config as auth_config


@validator_args
def auth_2fa_user_login(
    not_missing: types.Validator,
    unicode_safe: types.Validator,
    one_of: types.Validator,
) -> types.Schema:

    return {
        "login": [not_missing, unicode_safe],
        "password": [not_missing, unicode_safe],
        "mfa": [not_missing, unicode_safe],
        "mfa_type": [not_missing, unicode_safe, one_of(auth_config.ALLOWED_METHODS)],  # type: ignore
    }


@validator_args
def auth_2fa_validate_code(
    not_missing: types.Validator,
    unicode_safe: types.Validator,
    one_of: types.Validator,
) -> types.Schema:
    """TODO: it's the same as auth_2fa_user_login ?"""

    return {
        "login": [not_missing, unicode_safe],
        "password": [not_missing, unicode_safe],
        "mfa": [not_missing, unicode_safe],
        "mfa_type": [not_missing, unicode_safe, one_of(auth_config.ALLOWED_METHODS)],  # type: ignore
    }
