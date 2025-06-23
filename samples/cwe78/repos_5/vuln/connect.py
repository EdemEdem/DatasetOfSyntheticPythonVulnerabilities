#!/usr/bin/env python3
"""
Vulnerable Netcat wrapper (CWE-78):
  - No validation of --target or --port
  - Builds a single shell command string
  - Uses shell=True, allowing injection
"""

import argparse
import subprocess
import sys
import shutil

def pick_binary():
    # On Windows look for 'ncat', otherwise 'nc'
    if sys.platform.startswith("win"):
        return "ncat"
    return "nc"

def main():
    parser = argparse.ArgumentParser(description="Simple Netcat wrapper (vulnerable)")
    parser.add_argument("--target", required=True,
                        help="Target host or IP")
    parser.add_argument("--port", required=True,
                        help="Target port")
    args = parser.parse_args()
    
    bin_name = pick_binary()
    if shutil.which(bin_name) is None:
        print(f"Error: cannot find '{bin_name}' in PATH. On Windows you may need to `choco install ncat`.", file=sys.stderr)
        sys.exit(1)

    cmd = f"{bin_name} {args.target} {args.port}"
    print(f"Executing: {cmd}")
    subprocess.call(cmd, shell=True)  # CWE-78: shell=True + untrusted input

if __name__ == "__main__":
    main()
