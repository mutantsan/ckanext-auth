from __future__ import annotations

import logging
from typing import Any
from datetime import timedelta

import ckan.model as model
import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
from ckan.views.user import next_page_or_default, rotate_token
from ckan.lib.authenticator import default_authenticate

import ckanext.auth.utils as utils
from ckanext.auth import config
from ckanext.auth.model import UserSecret
from ckanext.auth.exceptions import ReplayAttackException

log = logging.getLogger(__name__)


@tk.blanket.actions
@tk.blanket.auth_functions
@tk.blanket.helpers
@tk.blanket.blueprints
@tk.blanket.config_declarations
@tk.blanket.cli
class AuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, "templates")
        tk.add_resource("assets", "auth")

    # IAuthenticator

    def login(self):
        extra_vars: dict[str, Any] = {}

        if tk.current_user.is_authenticated:
            return tk.render("user/logout_first.html", extra_vars)

        if tk.request.method != "POST":
            return tk.render("user/login.html", extra_vars)

        user_obj = authenticate(
            {
                "login": tk.get_or_bust(tk.request.form, "login"),
                "password": tk.get_or_bust(tk.request.form, "password"),
            }
        )

        if not user_obj:
            tk.h.flash_error(tk._("Login failed. Bad username or password."))
            return tk.render("user/login.html", extra_vars)

        if remember := tk.request.form.get("remember"):
            tk.login_user(
                user_obj, remember=True, duration=timedelta(milliseconds=int(remember))
            )
        else:
            tk.login_user(user_obj)

        rotate_token()

        return next_page_or_default(
            tk.request.args.get("next", tk.request.args.get("came_from"))
        )


def authenticate(identity: dict[str, str]) -> model.User | None:
    # Run through the CKAN auth sequence first, so we can hit the DB
    # in every case and make timing attacks a little more difficult.
    ckan_auth_result = default_authenticate(identity)

    if "login" not in identity:
        return None

    if utils.LoginManager.is_login_blocked(identity["login"]):
        return None

    if not ckan_auth_result:
        return utils.LoginManager.log_user_login_attempt(identity["login"])

    if not config.is_2fa_enabled():
        utils.LoginManager.reset_for_user(identity["login"])
        return ckan_auth_result

    # if the CKAN authenticator has successfully authenticated
    # then check the TOTP parameter to see if it is valid
    if authenticate_totp(identity["login"]):
        return ckan_auth_result

    # This means that the login form has been submitted
    # with an invalid TOTP code, bypassing the ajax
    # login() workflow in utils.login.
    # The username and password were fine, but the 2fa
    # code was missing or invalid
    return None


def authenticate_totp(user_name: str) -> str | None:
    user_secret = UserSecret.get_for_user(user_name)

    # if there is no totp configured, don't allow auth
    # shouldn't happen, login flow should create a user secret
    if not user_secret:
        return log.info(
            "2FA: Login attempted without MFA configured for: %s", user_name
        )

    if "code" not in tk.request.form:
        return log.info("2FA: Could not get MFA credentials from a request")

    try:
        user_secret.check_code(tk.request.form["code"])
    except ReplayAttackException as e:
        return log.warning(
            "2FA: Detected a possible replay attack for user: %s, context: %s",
            user_name,
            e,
        )

    return user_name
