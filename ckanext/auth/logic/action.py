from __future__ import annotations

import logging
from typing import Any

import ckan.model as model
import ckan.plugins.toolkit as tk
from ckan import types
from ckan.logic import validate

import ckanext.auth.utils as auth_utils
import ckanext.auth.config as auth_config
import ckanext.auth.logic.schema as schema
from ckanext.auth.model import UserSecret

log = logging.getLogger(__name__)


@validate(schema.auth_2fa_user_login)
def auth_2fa_user_login(
    context: types.Context, data_dict: types.DataDict
) -> dict[str, Any]:
    tk.check_access("auth_2fa_user_login", context, data_dict)

    result = None

    user = model.User.by_name(data_dict["login"])

    if (
        not user
        or not user.is_active
        or not user.validate_password(data_dict["password"])
    ):
        log.info("2FA: Login failed for %s", data_dict["login"])
        return {
            "success": False,
            "error": "Invalid login or password",
            "result": None,
        }

    user_secret = UserSecret.get_for_user(user.name)

    if not user_secret:
        user_secret = UserSecret.create_for_user(user.name)

    if data_dict["mfa_type"] == auth_config.METHOD_AUTHENTICATOR:
        return {
            "success": True,
            "error": None,
            "result": validate_totp(user_secret, data_dict),
        }

    success = auth_utils.send_mail_to_user(user)

    return {
        "success": success,
        "error": "Failed to send verification code" if not success else None,
        "result": None,
    }


def validate_totp(user_secret: UserSecret, data_dict: dict[str, Any]) -> dict[str, Any]:
    result = {}

    mfaConfigured = user_secret.last_access is not None

    if not mfaConfigured:
        result["totpSecret"] = user_secret.secret
        result["totpChallengerURI"] = user_secret.provisioning_uri

    result["mfaConfigured"] = mfaConfigured

    if data_dict["mfa"]:
        result["mfa_success"] = user_secret.check_code(
            data_dict["mfa"], verify_only=True
        )

        if result["mfa_success"]:
            log.info("2FA: Login succeeded for %s", data_dict["login"])
        else:
            log.info("2FA: User %s supplied an invalid 2FA code", data_dict["login"])

    result["totpSecret"] = user_secret.secret
    result["totpChallengerURI"] = user_secret.provisioning_uri

    return result


@validate(schema.auth_2fa_validate_code)
def auth_2fa_validate_code(
    context: types.Context, data_dict: types.DataDict
) -> dict[str, Any]:
    tk.check_access("auth_2fa_validate_code", context, data_dict)
