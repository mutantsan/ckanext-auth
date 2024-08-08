from __future__ import annotations

import logging
from functools import wraps
from typing import cast

from flask import Blueprint, request, jsonify, Response
from flask.views import MethodView

import ckan.types as types
from ckan.lib import helpers
from ckan.plugins import toolkit as tk, plugin_loaded
from ckan.logic import parse_params

from ckanext.auth import utils
from ckanext.auth.model import UserSecret

log = logging.getLogger(__name__)
auth = Blueprint("auth", __name__, url_prefix="/mfa")


def require_login(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if tk.current_user.is_anonymous:
            return tk.abort(401, tk._("You have to be logged in to access this page."))
        return func(*args, **kwargs)

    return decorated_view


class Configure2FA(MethodView):
    @require_login
    def get(self, user_id: str):
        try:
            user_dict = tk.get_action("user_show")(self.get_context(), {"id:": user_id})
        except tk.ObjectNotFound:
            tk.abort(404, tk._("User not found"))
        except tk.NotAuthorized:
            tk.abort(403, tk._("Not authorized to see this page"))

        extra_vars = {
            "user_id": user_id,
            "is_sysadmin": user_dict["sysadmin"],
            "is_myself": user_dict["name"] == tk.current_user.name,
            "user_dict": user_dict,
        }

        extra_vars.update(self._setup_totp_extra_vars(user_id))

        return tk.render(
            "auth/configure_2fa.html",
            extra_vars,
        )

    def get_context(self) -> types.Context:
        return {
            "user": tk.current_user.name,
            "auth_user_obj": tk.current_user,
        }

    @require_login
    def post(self, user_id: str):
        extra_vars = self._setup_totp_extra_vars(user_id)

        if extra_vars.get("mfa_test_valid"):
            tk.h.flash_success(
                tk._(
                    """
                    The code is valid. Your authenticator app is
                    now properly set up for future use."""
                )
            )
        else:
            tk.h.flash_error(
                tk._(
                    """The code is incorrect. Please try scanning
                    the QR code with your authenticator app again."""
                )
            )

        return tk.redirect_to("auth.configure_2fa", user_id=user_id)

    def _setup_totp_extra_vars(self, user_id: str):
        payload = parse_params(tk.request.form)
        extra_vars = {}

        user_secret = UserSecret.get_for_user(user_id)

        if not user_secret:
            return extra_vars

        test_code = cast(str, payload.get("code"))

        if request.method == "POST" and test_code:
            extra_vars["mfa_test_valid"] = user_secret.check_code(
                test_code, verify_only=True
            )

        return {
            "totp_secret": user_secret.secret,
            "totp_challenger_uri": user_secret.provisioning_uri,
        }


@auth.route("/configure_mfa/<user_id>/new", methods=["GET", "POST"])
@require_login
def regenerate_secret(user_id: str):
    utils.regenerate_user_secret(user_id)
    tk.h.flash_success(tk._("Your 2FA secret has been regenerated."))
    return helpers.redirect_to("auth.configure_2fa", user_id=user_id)


@auth.route("/send_verification_code", methods=["POST"])
def send_verification_code() -> Response:
    user_name: str = tk.get_or_bust(dict(tk.request.form), "login")

    utils.regenerate_user_secret(user_name)
    success = utils.send_verification_email_to_user(user_name)

    return jsonify(
        {
            "success": success,
            "error": "Failed to send verification code" if not success else None,
            "result": None,
        }
    )


if plugin_loaded("admin_panel"):
    from ckanext.ap_main.utils import ap_before_request
    from ckanext.ap_main.views.generics import ApConfigurationPageView

    charts_admin = Blueprint("auth_admin", __name__)
    charts_admin.before_request(ap_before_request)

    # class ConfigClearCacheView(MethodView):
    #     def post(self):
    #         if "invalidate-all-cache" in tk.request.form:
    #             cache.invalidate_all_cache()

    #         if "invalidate-redis-cache" in tk.request.form:
    #             cache.drop_redis_cache()

    #         if "invalidate-file-cache" in tk.request.form:
    #             cache.drop_file_cache()

    #         tk.h.flash_success(tk._("Cache has been cleared"))

    #         return tk.h.redirect_to("charts_view_admin.config")

    # charts_admin.add_url_rule(
    #     "/admin-panel/charts/clear-cache",
    #     view_func=ConfigClearCacheView.as_view("clear_cache"),
    # )
    charts_admin.add_url_rule(
        "/admin-panel/auth/config",
        view_func=ApConfigurationPageView.as_view(
            "config",
            "ckanext_auth_config",
            page_title=tk._("Auth config"),
        ),
    )


auth.add_url_rule(
    "/configure_2fa/<user_id>", view_func=Configure2FA.as_view("configure_2fa")
)


def get_blueprints():
    return [auth]
