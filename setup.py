"""
Setup script so `quickapi` can be installed / recognized as a package.
"""

from setuptools import setup, find_packages

setup(
    name="quickapi",
    version="0.9.0",
    description="A fictional Python web framework for CodeQL Model Editor demos",
    packages=find_packages(),
    python_requires=">=3.8",
)
