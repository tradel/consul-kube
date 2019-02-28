from setuptools import setup

setup(
    use_scm_version=True,
    entry_points='''
        [console_scripts]
        consul-kube = commands:main
    ''',
)