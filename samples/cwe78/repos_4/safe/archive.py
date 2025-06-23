import click
import os
import shutil
import subprocess

@click.command()
@click.argument("src_dir")
def archive(src_dir):
    """
    Safe: verifies src_dir exists as a directory, then
    uses a non‐shell API to create the archive.
    """
    # 1) Validate: must be an existing directory
    if not os.path.isdir(src_dir):
        click.echo("Error: invalid directory name", err=True)
        raise click.Abort()

    # 2a) Safe approach #1: shutil.make_archive
    shutil.make_archive("backup", "gztar", src_dir)
    click.echo(f"Created backup.tar.gz from {src_dir}")

    # 2b) Alternative safe approach using subprocess:
    # subprocess.run(
    #     ["tar", "-czf", "backup.tar.gz", src_dir],
    #     check=True
    # )
    # click.echo(f"Created backup.tar.gz from {src_dir}")

if __name__ == "__main__":
    archive()
