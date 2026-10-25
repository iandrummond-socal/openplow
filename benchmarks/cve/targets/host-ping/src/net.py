"""Reachability check for a host given by an operator."""

import subprocess


def ping(host):
    cmd = "ping -c 1 " + host
    return subprocess.run(cmd, shell=True, capture_output=True).returncode
