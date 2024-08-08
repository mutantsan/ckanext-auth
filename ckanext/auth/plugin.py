from __future__ import annotations

import logging

import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
from ckan import types

import ckanext.auth.utils as utils

log = logging.getLogger(__name__)


@tk.blanket.actions
@tk.blanket.auth_functions
@tk.blanket.helpers
@tk.blanket.blueprints
@tk.blanket.config_declarations
@tk.blanket.cli
class AuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ISignal)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, "templates")
        tk.add_resource("assets", "auth")

    # ISignal

    def get_signal_subscriptions(self) -> types.SignalMapping:
        return {
            tk.signals.ckanext.signal("ap_main:collect_config_sections"): [
                self.collect_config_sections_subs,
            ],
            tk.signals.ckanext.signal("ap_main:collect_config_schemas"): [
                self.collect_config_schemas_subs,
            ],
        }

    @staticmethod
    def collect_config_sections_subs(sender: None):
        return {
            "name": "Auth",
            "configs": [
                {
                    "name": "Configuration",
                    "blueprint": "auth_admin.config",
                    "info": "Auth settings",
                },
            ],
        }

    @staticmethod
    def collect_config_schemas_subs(sender: None):
        return ["ckanext.auth:config_schema.yaml"]

    # IAuthenticator

    def login(self):
        return utils.login()
