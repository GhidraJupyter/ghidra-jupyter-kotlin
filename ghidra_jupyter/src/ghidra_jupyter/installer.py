import argparse
import os
import re
import shutil
import zipfile
from tempfile import TemporaryDirectory
from typing import Optional, Tuple
from packaging import version
from pathlib import Path

import requests
from tqdm import tqdm

REPO = "GhidraJupyter/ghidra-jupyter-kotlin"
# NAME_PATTERN = r"GhidraJupyterKotlin[v0-9.\-_]*\.zip"
NAME_PATTERN = r"ghidra_(.+)_PUBLIC_(\d{8})_GhidraJupyterKotlin.zip"

def download_file(url: str, path: str):
    with requests.get(url, stream=True) as response:
        response.raise_for_status()

        total_size_in_bytes = int(response.headers.get("content-length", 0)) or None
        block_size = 1024  # 1 Kibibyte

        with open(path, "wb") as f, tqdm(
            total=total_size_in_bytes, unit="iB", unit_scale=True
        ) as progress_bar:
            for chunk in response.iter_content(chunk_size=block_size):
                f.write(chunk)
                progress_bar.update(len(chunk))


def _install_from_path(ghidra_install_dir: str, extension_path: str):
    # First, remove the extension if it already exists
    install_path = os.path.join(
        ghidra_install_dir, "Ghidra", "Extensions", "GhidraJupyterKotlin"
    )
    print(f"Installing extension to {install_path}")
    shutil.rmtree(
        install_path,
        ignore_errors=True,
    )

    with zipfile.ZipFile(extension_path) as zip_ref:
        zip_ref.extractall(os.path.join(ghidra_install_dir, "Ghidra", "Extensions"))


def _get_ghidra_dir(ghidra_install_dir: Optional[str]) -> str:
    return ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR")


def _get_ghidra_version(ghidra_install_dir: Optional[str]) -> version.Version:
    app_properties = os.path.join(ghidra_install_dir, "Ghidra", "application.properties")
    with open(app_properties, "r") as f:
        for line in f.readlines():
            key, value = line.split("=")
            if key == "application.version":
                return version.parse(value)


def get_download_url(repo, name_pattern) -> Tuple[str, version.Version]:
    release = requests.get(f"https://api.github.com/repos/{repo}/releases/latest")
    release.raise_for_status()
    for asset in release.json()["assets"]:
        m = re.match(name_pattern, asset["name"])
        if m:
            extension_version = version.parse(m.group(1))
            return asset["browser_download_url"], extension_version



def install_extension(
    ghidra_install_dir: Optional[str],
    extension_path: Optional[str],
    extension_url: Optional[str],
):
    ghidra_install_dir = _get_ghidra_dir(ghidra_install_dir)
    ghidra_version = _get_ghidra_version(ghidra_install_dir)

    if not ghidra_install_dir:
        print("Missing $GHIDRA_INSTALL_DIR")
        return

    if extension_path:
        _install_from_path(ghidra_install_dir, extension_path)

    else:
        with TemporaryDirectory() as tempdir:
            extension_path = os.path.join(tempdir, "Extension.zip")
            if extension_url is None:
                extension_url, extension_version = get_download_url(REPO, NAME_PATTERN)
                print("Detected Ghidra Version: ", ghidra_version)
                print("Extension Version: ", extension_version)
                if extension_version.major != ghidra_version.major:
                    print("ERROR: Major version of Ghidra (%s) and Extension (%s) don't match, refusing to install" %
                          (ghidra_version, extension_version))
                    return
                elif ghidra_version > extension_version:
                    print("WARNING: Your Ghidra version is newer than the extension version")
                    print("There could be some unresolved compatibility issue or we forgot to bump the CI version")
                    print("Please check https://github.com/%s" % REPO)
                elif extension_version > ghidra_version:
                    print("!WARNING! " * 10)
                    print("WARNING: Ghidra Version is %s, but extension_version is %s"
                          % (ghidra_version, extension_version))
                    print("WARNING: Extension will still be installed, but might encounter unpredictable issues. "
                          "Please update your Ghidra install or manually install an older release")
                    print("!WARNING! " * 10)

            print(f"Downloading Ghidra extension from {extension_url}")
            download_file(extension_url, extension_path)
            print("Download complete.")
            _install_from_path(ghidra_install_dir, extension_path)

    print("Installation Complete.")


def remove_extension(ghidra_install_dir: Optional[str]):
    ghidra_install_dir = _get_ghidra_dir(ghidra_install_dir)
    if not ghidra_install_dir:
        print("Missing $GHIDRA_INSTALL_DIR")
        return

    install_path = os.path.join(
        ghidra_install_dir, "Ghidra", "Extensions", "GhidraJupyterKotlin"
    )
    print(f"Removing extension at {install_path}")
    shutil.rmtree(
        install_path,
        ignore_errors=True,
    )

    print("Extension removed.")


def create_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    install_extension = subparsers.add_parser("install-extension")
    install_extension.add_argument(
        "--ghidra",
        nargs="?",
        help="Ghidra install directory. Defaults to $GHIDRA_INSTALL_DIR",
    )
    install_extension.add_argument(
        "--extension-path",
        nargs="?",
        help="Path to a local .zip of the extension",
    )
    install_extension.add_argument(
        "--extension-url",
        nargs="?",
        help="URL to download the extension from",
    )

    remove_extension = subparsers.add_parser("remove-extension")
    remove_extension.add_argument(
        "--ghidra",
        nargs="?",
        help="Ghidra install directory. Defaults to $GHIDRA_INSTALL_DIR",
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "install-extension":
        install_extension(args.ghidra, args.extension_path, args.extension_url)

    elif args.command == "remove-extension":
        remove_extension(args.ghidra)


if __name__ == "__main__":
    main()
