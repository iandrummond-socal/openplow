"""Reachability check — minimal reproduction of OS command injection (CWE-78).

Representative of many real CVEs: a user-supplied host is interpolated into a
shell command run with shell=True, so '; <cmd>' executes arbitrary commands.
"""

import subprocess


def ping(host):
    # VULN (CWE-78): host concatenated into a shell command line.
    cmd = "ping -c 1 " + host
    return subprocess.run(cmd, shell=True, capture_output=True).returncode
