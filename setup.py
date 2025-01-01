from setuptools import setup, find_packages

setup(
    name="webslayer",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "requests",
        "python-owasp-zap-v2.4",
        "python-nmap",
        "tqdm",
        "Jinja2",
    ],
    entry_points={
        "console_scripts": [
            "webslayer=webslayer:main",
        ],
    },
    author="Oxihash",
    author_email="oxihash@example.com",
    description="An automated web application testing and report generating tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/oxihash/webslayer",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
