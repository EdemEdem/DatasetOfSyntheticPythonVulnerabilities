import click
import os

@click.command()
@click.argument("src_dir")
def archive(src_dir):
    """
    Vulnerable: creates backup.tar.gz by passing src_dir
    unvalidated into a shell command (CWE-78).
    """
    # WARNING: no validation or escaping of src_dir
    cmd = f"tar -czf backup.tar.gz {src_dir}"
    os.system(cmd)  # <-- command injection possible!
    click.echo(f"Created backup.tar.gz from {src_dir}")

if __name__ == "__main__":
    archive()
