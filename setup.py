from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bountybot",
    version="2.3.0",
    author="Security Team",
    description="Enterprise-grade AI-powered bug bounty validation framework with REST API and webhooks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bountybot",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.0",
        "pyyaml>=6.0",
        "python-dotenv>=1.0.0",
        "jinja2>=3.1.0",
        "anthropic>=0.18.0",
        "openai>=1.12.0",
        "google-generativeai>=0.3.0",
        "beautifulsoup4>=4.12.0",
        "markdown>=3.5.0",
        "lxml>=4.9.0",
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "rich>=13.7.0",
        "colorama>=0.4.6",
        "python-dateutil>=2.8.0",
        "tiktoken>=0.5.0",
        "sqlalchemy>=2.0.0",
        "psycopg2-binary>=2.9.0",
        "fastapi>=0.109.0",
        "uvicorn[standard]>=0.27.0",
        "pydantic>=2.5.0",
        "httpx>=0.26.0",
        "python-multipart>=0.0.6",
    ],
    entry_points={
        "console_scripts": [
            "bountybot=bountybot.cli:main",
            "bountybot-api=bountybot.api.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "bountybot": [
            "config/*.yaml",
            "knowledge/vulnerabilities/*.yaml",
            "outputs/templates/*.html",
            "outputs/templates/*.md",
        ],
    },
)

