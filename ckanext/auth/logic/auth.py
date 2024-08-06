from __future__ import annotations

from typing import Any

from ckan.types import Context


def auth_2fa_user_login(context: Context, data_dict: dict[str, Any]):
    return {"success": True}
