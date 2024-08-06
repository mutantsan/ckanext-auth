from __future__ import annotations

import logging
from typing import cast

import ckan.plugins as p
import ckan.model as model
import ckan.lib.mailer as ckan_mailer
import ckan.plugins.toolkit as tk
from ckan.lib.redis import connect_to_redis

from ckanext.auth import config as auth_config
from ckanext.auth.model import UserSecret


log = logging.getLogger(__name__)


def send_verification_email_to_user(user_id: str) -> bool:
    user = model.User.get(user_id)

    if not user or not user.email:
        return False

    code = get_email_verification_code(user)

    data = {
        "verification_code": code,
        "site_url": tk.config["ckan.site_url"],
        "site_title": tk.config["ckan.site_title"],
        "user_name": user.display_name,
        "subject": tk._("Verification code for your account"),
        "body": f"Your verification code is: {code}",
    }

    if p.plugin_loaded("mailcraft"):
        from ckanext.mailcraft.utils import get_mailer

        get_mailer().mail_recipients(
            subject=data["subject"],
            recipients=[user.email],
            body=data["body"],
            body_html=tk.render(
                "auth/emails/verification_code.html",
                extra_vars=data,
            ),
        )
    else:
        try:
            ckan_mailer.mail_user(
                recipient=user,
                subject=tk._("Verification code for your account"),
                body=data["body"],
                body_html=tk.render(
                    "auth/emails/verification_code.html",
                    extra_vars=data,
                ),
            )
        except ckan_mailer.MailerException:
            return False

    return True


def get_email_verification_code(user: model.User) -> str:
    user_secret = UserSecret.get_for_user(user.name)

    if not user_secret:
        user_secret = UserSecret.create_for_user(user.name)

    return user_secret.get_code()


def regenerate_user_secret(user_id: str) -> str:
    """Regenerate the secret for a user.

    Args:
        user_id (str): The id of the user

    Returns:
        str: The new secret
    """

    user = model.User.get(user_id)

    if not user:
        raise tk.ObjectNotFound("User not found")

    user_secret = UserSecret.create_for_user(user.name)

    log.info("2FA: Rotated the 2fa secret for user %s", user_id)

    return cast(str, user_secret.secret)


class LoginManager:
    login_attempts_key = "ckanext-auth:login_attempts:{}"
    blocked_key = "ckanext-auth:blocked:{}"

    @classmethod
    def is_login_blocked(cls, user_id: str) -> bool:
        """Check if a user is blocked from logging in."""
        return bool(connect_to_redis().get(cls.blocked_key.format(user_id)))

    @classmethod
    def block_user_login(cls, user_id: str) -> None:
        """Block a user from logging in for a certain amount of time."""
        connect_to_redis().setex(
            cls.blocked_key.format(user_id),
            auth_config.get_2fa_login_timeout(),
            1,
        )

    @classmethod
    def log_user_login_attempt(cls, user_id: str) -> None:
        """Log a login attempt for a user."""
        conn = connect_to_redis()

        attempts = conn.incr(cls.login_attempts_key.format(user_id))

        if attempts >= auth_config.get_2fa_max_attempts():
            cls.block_user_login(user_id)
            return

    @classmethod
    def get_user_login_attempts(cls, user_id: str) -> int:
        """Get the number of login attempts for a user."""
        return int(connect_to_redis().get(cls.login_attempts_key.format(user_id)) or 0)

    @classmethod
    def reset_for_user(cls, user_id: str) -> None:
        """Reset the login attempts for a user."""
        log.info("2FA: Resetting login attempts for user %s", user_id)

        connect_to_redis().delete(cls.login_attempts_key.format(user_id))
        connect_to_redis().delete(cls.blocked_key.format(user_id))
