import glob

from setuptools import find_packages, setup

GITHUB_URL = "https://github.com/GhidraJupyter/ghidra-jupyter-kotlin"

LONG_DESCRIPTION = f"""
# Ghidra-Jupyter

A Jupyter kernel (notebook & QtConsole) plugin for Ghidra.

Currently supporting [Kotlin-Jupyter](https://github.com/Kotlin/kotlin-jupyter).

For info and installation see the [github repo]({GITHUB_URL}). 
"""


def is_requirement(line):
    return not line.startswith("-e") and not line.startswith(".")


def get_requirements(extra=None):
    if extra:
        filename = f"requirements.{extra}.txt"
    else:
        filename = "requirements.txt"

    with open(filename) as f:
        return [line for line in f.read().splitlines() if is_requirement(line)]


DATA_FILES = [
    ("share/jupyter/kernels/ghidra-kotlin", glob.glob("kernel/*")),
]


PACKAGES = find_packages(where="src")
INSTALL_REQUIRES = get_requirements()
setup(
    name="ghidra_jupyter",
    version="1.1.0",
    packages=PACKAGES,
    package_dir={"": "src"},
    include_package_data=True,
    url=GITHUB_URL,
    license="MIT License",
    author="GhidraJupyter",
    author_email="",
    description="A Jupyter kernel for Ghidra",
    long_description_content_type="text/markdown",
    long_description=LONG_DESCRIPTION,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=INSTALL_REQUIRES,
    entry_points={
        "console_scripts": [
            "ghidra-jupyter=ghidra_jupyter.installer:main",
        ],
    },
    data_files=DATA_FILES,
    python_requires=">=3.6",
)
