import click
import os

@click.command()
@click.argument("src_dir")
def archive(src_dir):
    cmd = f"tar -czf backup.tar.gz {src_dir}"
    os.system(cmd)  
    click.echo(f"Created backup.tar.gz from {src_dir}")

if __name__ == "__main__":
    archive()
