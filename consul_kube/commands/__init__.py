import click

from consul_kube.lib import color


@click.group()
@click.option('-debug/-no-debug', default=False, help='Enables or disables verbose output.')
@click.option('-save-certs/-no-save-certs', default=False, help='Save a copy of any retrieved certs.')
@click.option('-context', help='Choose a context from your kubeconfig.')
@click.pass_context
def main(ctx: click.Context, debug: bool, save_certs: bool):
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug
    ctx.obj['save_certs'] = save_certs
    color.debug_mode = debug
    color.write_certs = save_certs
