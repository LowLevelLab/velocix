from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="velocix",
    version="0.1.3",
    author="Magi Sharma",
    author_email="sharmamagio0@gmail.com",
    description="A learning project - ASGI web framework built to understand async Python patterns",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/magi8101/velocix",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'velocix=velocix.cli:cli',
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: Education",
        "Framework :: AsyncIO",
        "Environment :: Web Environment",
    ],
    keywords="web framework, async, asgi, learning project, educational, starlette, fastapi",
    project_urls={
        "Source": "https://github.com/magi8101/velocix",
        "Issues": "https://github.com/magi8101/velocix/issues",
    },
)
