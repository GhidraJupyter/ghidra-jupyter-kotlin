import sys
import os
import psutil
import attr

PROXY_ENV_VAR = "GHIDRA_JUPYTER_PROXY"


@attr.s(auto_attribs=True, frozen=True, slots=True)
class ProxyPaths:
    pid: str
    path: str


def get_proxy_paths():
    base = os.environ.get(PROXY_ENV_VAR)
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".ghidra", "notebook_proxy")

    return ProxyPaths(
        pid=base + ".pid",
        path=base + ".path",
    )


def main():
    print("starting!")
    proxy_paths = get_proxy_paths()

    with open(proxy_paths.path, "w") as f:
        f.write(sys.argv[1])

    with open(proxy_paths.pid, "r") as f:
        pid = int(f.read().strip())

    psutil.Process(pid=pid).wait()


if __name__ == "__main__":
    main()
