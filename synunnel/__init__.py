"""Application Synunnel."""

__version__ = "0.2.0a1"
VERSION_LABEL = "0.2 alpha"

from .web import create_app

__all__ = ["create_app"]
