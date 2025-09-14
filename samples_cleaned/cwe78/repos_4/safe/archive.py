import click
import os
import shutil
import subprocess

@click.command()
@click.argument("src_dir")
def archive(src_dir):
    if not os.path.isdir(src_dir):
        click.echo("Error: invalid directory name", err=True)
        raise click.Abort()

    shutil.make_archive("backup", "gztar", src_dir)
    click.echo(f"Created backup.tar.gz from {src_dir}")


if __name__ == "__main__":
    archive()
