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
        "Jinja2>=3.1.2",
        "MarkupSafe>=2.1.3",
        "itsdangerous>=2.1.2",
        "click>=8.1.7",
        "blinker>=1.6.2",
        "waitress>=2.1.2",
        "python-dateutil>=2.8.2",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-flask>=1.2.0",
            "flake8>=6.1.0",
            "black>=23.7.0",
            "pylint>=2.17.5",
            "python-dotenv>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "dh-webapp=app:main",
        ],
    },
    include_package_data=True,
)
