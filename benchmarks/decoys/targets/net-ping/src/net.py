"""Reachability check for a host given by an operator."""

import ipaddress
import re
import subprocess

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")


def _valid_host(host):
    if not isinstance(host, str):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME.match(host))


def ping(host):
    if not _valid_host(host):
        raise ValueError(f"invalid host: {host!r}")
    # argv list, no shell; "--" ends options so the host can never be a flag.
    return subprocess.run(["ping", "-c", "1", "-W", "2", "--", host],
                          capture_output=True, timeout=10, check=False).returncode
