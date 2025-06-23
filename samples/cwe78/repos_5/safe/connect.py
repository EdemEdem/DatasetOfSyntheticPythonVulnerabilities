#!/usr/bin/env python3
"""
Sanitized Netcat wrapper:
  - Validates target against hostname/IP regex
  - Validates port is numeric (1–65535)
  - Calls nc without shell=True to avoid injection
"""

import argparse
import subprocess
import re
import sys
import shutil

# Regex for IPv4 dotted-quad
IPV4_REGEX = re.compile(
    r'^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# Simple hostname regex (labels 1–63 chars, letters/digits/hyphens, no leading/trailing hyphen)
HOSTNAME_REGEX = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)'          
    r'(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
)

def pick_binary():
    # On Windows look for 'ncat', otherwise 'nc'
    if sys.platform.startswith("win"):
        return "ncat"
    return "nc"

def validate_target(host: str) -> bool:
    """Return True if host is a valid IPv4 address or hostname."""
    return bool(IPV4_REGEX.match(host)) or bool(HOSTNAME_REGEX.match(host))

def validate_port(port: str) -> bool:
    """Return True if port is an integer between 1 and 65535."""
    if not port.isdigit():
        return False
    num = int(port)
    return 1 <= num <= 65535

def main():
    parser = argparse.ArgumentParser(description="Simple Netcat wrapper (safe)")
    parser.add_argument("--target", required=True,
                        help="Target host or IP")
    parser.add_argument("--port", required=True,
                        help="Target port")
    args = parser.parse_args()

    # Validate inputs
    if not validate_target(args.target):
        print(f"Error: invalid target '{args.target}'", file=sys.stderr)
        sys.exit(1)

    if not validate_port(args.port):
        print(f"Error: invalid port '{args.port}'", file=sys.stderr)
        sys.exit(1)

	# 2) Locate binary
    bin_name = pick_binary()
    if shutil.which(bin_name) is None:
        print(f"Error: cannot find '{bin_name}' in PATH. On Windows you may need to `choco install ncat`.", file=sys.stderr)
        sys.exit(1)

    # Safe: pass args as a list, no shell expansion
    cmd = [bin_name, args.target, args.port]
    print(f"Executing: {' '.join(cmd)}")
    return_code = subprocess.call(cmd)

    if return_code != 0:
        sys.exit(return_code)

if __name__ == "__main__":
    main()
