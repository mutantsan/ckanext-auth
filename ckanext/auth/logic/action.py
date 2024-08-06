from __future__ import annotations

import logging
from typing import Any, TypedDict

import ckan.model as model
import ckan.plugins.toolkit as tk
from ckan import types
from ckan.logic import validate

import ckanext.auth.utils as utils
import ckanext.auth.config as auth_config
import ckanext.auth.logic.schema as schema
from ckanext.auth.model import UserSecret

log = logging.getLogger(__name__)


class LoginResponse(TypedDict):
    success: bool
    error: str | None
    result: dict[str, Any] | None


@validate(schema.auth_2fa_user_login)
def auth_2fa_user_login(
    context: types.Context, data_dict: types.DataDict
) -> LoginResponse:
    tk.check_access("auth_2fa_user_login", context, data_dict)

    user = model.User.by_name(data_dict["login"])

    if (
        not user
        or not user.is_active
        or not user.validate_password(data_dict["password"])
    ):
        log.info("2FA: Login failed for %s", data_dict["login"])
        return LoginResponse(
            success=False,
            error=tk._("Invalid login or password"),
            result=None,
        )

    if utils.LoginManager.is_login_blocked(data_dict["login"]):
        log.info("2FA: User %s is blocked from logging in", data_dict["login"])
        return LoginResponse(
            success=False,
            error=tk._("Too many login attempts"),
            result=None,
        )

    utils.LoginManager.log_user_login_attempt(data_dict["login"])
    user_secret = UserSecret.get_for_user(user.name)

    if not user_secret:
        user_secret = UserSecret.create_for_user(user.name)

    if data_dict["mfa_type"] == auth_config.METHOD_AUTHENTICATOR:
        result = validate_totp(user_secret, data_dict)

        return LoginResponse(
            success=result["mfa_success"],
            error=(
                "The verification code is invalid"
                if not result["mfa_success"]
                else None
            ),
            result=result,
        )

    elif data_dict["mfa_type"] == auth_config.METHOD_EMAIL:
        success = validate_email(user_secret, data_dict)

        return LoginResponse(
            success=success,
            error="The verification code is invalid" if not success else None,
            result={"valid": success},
        )

    raise ValueError("Invalid MFA type")


def validate_totp(user_secret: UserSecret, data_dict: dict[str, Any]) -> dict[str, Any]:
    result = {}

    mfaConfigured = user_secret.last_access is not None

    if not mfaConfigured:
        result["totpSecret"] = user_secret.secret
        result["totpChallengerURI"] = user_secret.provisioning_uri

    result["mfaConfigured"] = mfaConfigured

    if data_dict["code"]:
        result["mfa_success"] = user_secret.check_code(
            data_dict["code"], verify_only=True
        )

        if result["mfa_success"]:
            log.info("2FA: Login succeeded for %s", data_dict["login"])
        else:
            log.info("2FA: User %s supplied an invalid 2FA code", data_dict["login"])

    result["totpSecret"] = user_secret.secret
    result["totpChallengerURI"] = user_secret.provisioning_uri

    return result


def validate_email(user_secret: UserSecret, data_dict: dict[str, Any]) -> bool:
    return user_secret.check_code(data_dict["code"])


@validate(schema.auth_2fa_user_login)
def auth_2fa_check_credentials(
    context: types.Context, data_dict: types.DataDict
) -> LoginResponse:
    tk.check_access("auth_2fa_user_login", context, data_dict)

    user = model.User.by_name(data_dict["login"])

    if (
        not user
        or not user.is_active
        or not user.validate_password(data_dict["password"])
    ):
        log.info("2FA: Login failed for %s", data_dict["login"])
        return LoginResponse(
            success=False,
            error=tk._("Invalid login or password"),
            result=None,
        )

    if utils.LoginManager.is_login_blocked(data_dict["login"]):
        log.info("2FA: User %s is blocked from logging in", data_dict["login"])
        return LoginResponse(
            success=False,
            error=tk._("Too many login attempts"),
            result=None,
        )

    return LoginResponse(success=True, error=None, result=None)
