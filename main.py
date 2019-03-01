#!/usr/bin/env python3

from consul_kube.commands import main
from consul_kube.commands.validate import validate  # noqa: F401, pylint: disable=W0611
from consul_kube.commands.rotate import rotate  # noqa: F401, pylint: disable=W0611


def script_entry():
    main(obj={})  # pylint: disable=E1120,E1123


if __name__ == '__main__':
    script_entry()
