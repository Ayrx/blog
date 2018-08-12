import click

from app.generate import build_site
from app.serve import serve_site


@click.group()
def cli():
    pass


@cli.command()
def build():
    build_site()


@cli.command()
def serve():
    serve_site()
