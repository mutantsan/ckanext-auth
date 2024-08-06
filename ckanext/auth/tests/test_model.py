from __future__ import annotations

import pytest

import ckan.plugins.toolkit as tk
from ckan.tests.helpers import call_action

from ckanext.auth.model import UserSecret


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestUserSecretModel:
    def test_get_secret_for_user_missing(self, user):
        assert not UserSecret.get_for_user(user["name"])

    def test_create_for_user(self, user):
        secret = UserSecret.create_for_user(user["name"])

        assert secret.user_id == user["id"]
        assert secret.secret
        assert secret.last_access is None

    def test_get_secret_for_user(self, user):
        """The secret can be retrieved by user name or user ID."""
        secret = UserSecret.create_for_user(user["name"])

        assert UserSecret.get_for_user(user["name"]) == secret
        assert UserSecret.get_for_user(user["id"]) == secret

    def test_calling_create_again_rotates_the_secret(self, user):
        secret = UserSecret.create_for_user(user["name"])
        old_secret = secret.secret
        secret = UserSecret.create_for_user(user["name"])
        assert secret.secret != old_secret
