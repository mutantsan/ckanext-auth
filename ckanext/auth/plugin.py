from __future__ import annotations

import ckan.plugins as plugins
import ckan.plugins.toolkit as tk


@tk.blanket.actions
@tk.blanket.auth_functions
@tk.blanket.helpers
@tk.blanket.blueprints
@tk.blanket.config_declarations
class AuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, "templates")
        tk.add_resource("assets", "auth")
