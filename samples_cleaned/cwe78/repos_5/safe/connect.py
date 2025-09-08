
import argparse
import subprocess
import re
import sys
import shutil

IPV4_REGEX = re.compile(
    r'^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

HOSTNAME_REGEX = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)'          
    r'(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
)

def pick_binary():
    if sys.platform.startswith("win"):
        return "ncat"
    return "nc"

def validate_target(host: str) -> bool:
    return bool(IPV4_REGEX.match(host)) or bool(HOSTNAME_REGEX.match(host))

def validate_port(port: str) -> bool:
    if not port.isdigit():
        return False
    num = int(port)
    return 1 <= num <= 65535

def main():
    parser = argparse.ArgumentParser(description="Simple Netcat wrapper")
    parser.add_argument("--target", required=True,
                        help="Target host or IP")
    parser.add_argument("--port", required=True,
                        help="Target port")
    args = parser.parse_args()

    if not validate_target(args.target):
        print(f"Error: invalid target '{args.target}'", file=sys.stderr)
        sys.exit(1)

    if not validate_port(args.port):
        print(f"Error: invalid port '{args.port}'", file=sys.stderr)
        sys.exit(1)

    bin_name = pick_binary()
    if shutil.which(bin_name) is None:
        print(f"Error: cannot find '{bin_name}' in PATH. On Windows you may need to `choco install ncat`.", file=sys.stderr)
        sys.exit(1)

    cmd = [bin_name, args.target, args.port]
    print(f"Executing: {' '.join(cmd)}")
    return_code = subprocess.call(cmd)

    if return_code != 0:
        sys.exit(return_code)

if __name__ == "__main__":
    main()
