"""Application Synunnel."""

__version__ = "0.1.0a1"
VERSION_LABEL = "0.1 alpha"

from .web import create_app

__all__ = ["create_app"]
