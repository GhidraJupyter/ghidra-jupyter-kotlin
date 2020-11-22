import argparse
import os
import re
import shutil
import zipfile
from tempfile import TemporaryDirectory
from typing import Optional

import requests
from tqdm import tqdm

REPO = "GhidraJupyter/ghidra-jupyter-kotlin"
NAME_PATTERN = r"GhidraJupyterKotlin[v0-9.\-_]*\.zip"


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


def get_download_url(repo, name_pattern):
    release = requests.get(f"https://api.github.com/repos/{repo}/releases/latest")
    release.raise_for_status()
    for asset in release.json()["assets"]:
        if re.match(name_pattern, asset["name"]):
            return asset["browser_download_url"]


def install_extension(
    ghidra_install_dir: Optional[str],
    extension_path: Optional[str],
    extenion_url: Optional[str],
):
    ghidra_install_dir = _get_ghidra_dir(ghidra_install_dir)
    if not ghidra_install_dir:
        print("Missing $GHIDRA_INSTALL_DIR")
        return

    if extension_path:
        _install_from_path(ghidra_install_dir, extension_path)

    else:
        with TemporaryDirectory() as tempdir:
            extension_path = os.path.join(tempdir, "Extension.zip")
            extenion_url = extenion_url or get_download_url(REPO, NAME_PATTERN)
            print(f"Downloading Ghidra extension from {extenion_url}")
            download_file(extenion_url, extension_path)
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
