import click

debug_mode = False
write_certs = True
groovy = True


def debug(msg: str) -> None:
    if debug_mode:
        click.secho(f' [ ] {msg}')


def section(msg: str) -> None:
    click.echo()
    click.secho(f'{msg}', bold=True)


def info(msg: str) -> None:
    click.secho(f' [*] {msg}', bold=True)


def error(msg: str) -> None:
    global groovy
    groovy = False
    click.secho(f' [!] {msg}', fg='red', err=True)


def success(msg: str) -> None:
    click.secho(f' [+] {msg}', fg='green')


def color_assert(condition: bool, fail_msg: str, success_msg: str = None) -> bool:
    if not condition:
        error(fail_msg)
        return False
    elif success_msg:
        success(success_msg)
        return True
    else:
        return True
