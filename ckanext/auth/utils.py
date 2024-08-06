from __future__ import annotations

import logging
from typing import Any, cast

import ckan.plugins as p
import ckan.model as model
import ckan.lib.mailer as ckan_mailer
import ckan.plugins.toolkit as tk

from ckanext.auth.model import UserSecret


log = logging.getLogger(__name__)


def send_verification_email_to_user(user_id: str) -> bool:
    user = model.User.get(user_id)

    if not user or not user.email:
        return False

    code = get_email_verification_code(user)
    data = {
        "verification_code": get_email_verification_code(user),
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
