from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="command-line-threat-analyzer",
    version="1.0.0",
    author="Rohit",
    author_email="your-email@example.com",  # Replace with actual email
    description="A comprehensive cybersecurity tool for detecting and analyzing suspicious command line activities across Windows, Linux, and macOS platforms.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/command-line-threat-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Logging",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "clta-analyze=log_analyzer:main",
            "clta-web=web_app:main",  # This won't work directly with streamlit, but we'll document it
        ],
    },
    include_package_data=True,
    keywords=["cybersecurity", "threat-analysis", "command-line", "log-analysis", "security-tools"],
)