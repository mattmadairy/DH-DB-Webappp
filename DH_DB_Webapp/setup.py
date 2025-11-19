"""
Setup script for DH Member Database Web Application
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dh-member-database",
    version="1.0.0",
    author="Matt Madairy",
    description="A Flask web application for managing member database",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mattmadairy/DH-DB-Webappp",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Framework :: Flask",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Flask>=3.0.0",
        "Werkzeug>=3.0.1",
    ],
    entry_points={
        "console_scripts": [
            "dh-webapp=app:main",
        ],
    },
    include_package_data=True,
)
