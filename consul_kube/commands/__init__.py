import click

from consul_kube import __version__
from consul_kube.lib import color
from consul_kube.commands.rotate import rotate_command
from consul_kube.commands.validate import validate_command


@click.group()
@click.option('-debug/-no-debug', default=False,
              help='Enables or disables verbose output.')
@click.option('-save-certs/-no-save-certs', default=False,
              help='Save a copy of any retrieved certs.')
@click.option('-context', 'context_name',
              help='Choose a context from your kubeconfig.')
@click.version_option(__version__, '-version')
@click.help_option('-help')
@click.pass_context
def main(ctx: click.Context, debug: bool, save_certs: bool, context_name: str) -> None:
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug
    ctx.obj['save_certs'] = save_certs
    color.debug_mode = debug
    color.write_certs = save_certs


@main.command()
@click.option('-namespace', default='default', help='Kubernetes namespace where we can find Consul.')
@click.pass_context
def validate(ctx: click.Context, namespace: str) -> None:
    """Checks the certificates for every injected pod."""
    ctx.obj['namespace'] = namespace
    validate_command(ctx)


@main.command()
@click.pass_context
def rotate(ctx: click.Context) -> None:
    """Forces the Consul Connect CA to rotate its root certificate."""
    rotate_command(ctx)
