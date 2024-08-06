from __future__ import annotations

import logging

import click

from ckanext.auth import utils

logger = logging.getLogger(__name__)

__all__ = [
    "auth",
]


@click.group()
def auth():
    pass


@auth.command()
@click.argument("username")
def reset_secret(username):
    utils.regenerate_user_secret(username)


@auth.command()
@click.argument("username")
def unblock_user(username):
    utils.LoginManager.reset_for_user(username)
