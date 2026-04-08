"""
Fallback setup.py for pip versions and Python builds that can't
resolve the pyproject.toml build backend automatically.
This file is intentionally minimal — all real config is in pyproject.toml.
"""
from setuptools import setup

if __name__ == "__main__":
    setup()
