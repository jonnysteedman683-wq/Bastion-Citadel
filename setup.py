"""Setup script for Bastion-Citadel."""

from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="bastion-citadel",
    version="0.1.0",
    description="Autonomous Security Agent Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Bastion-Citadel Team",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.8.0",
        "click>=8.0.0",
    ],
    entry_points={
        "console_scripts": [
            "bastion=bastion_citadel.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    keywords=[
        "security",
        "monitoring",
        "scanner",
        "vulnerability",
        "agent",
        "bastion",
        "citadel",
    ],
)
