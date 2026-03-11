from setuptools import setup, find_packages

setup(
    name="vaultless",
    version="0.1.0",
    description="Git-architecture secrets manager with post-quantum encryption and SOC-2 evidence.",
    python_requires=">=3.11",
    packages=find_packages(include=["cli*", "server*", "intent*"]),
    install_requires=[
        "fastapi>=0.111",
        "uvicorn[standard]>=0.29",
        "click>=8.1",
        "rich>=13.7",
        "cryptography>=42.0",
        "httpx>=0.27",
        "pydantic>=2.0",
    ],
    extras_require={
        "pq": ["liboqs-python>=0.10"],  # yay -S liboqs first
    },
    entry_points={
        "console_scripts": [
            "vaultless=cli.vaultless:cli",
        ],
    },
)
