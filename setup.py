from setuptools import setup

setup(
    use_scm_version=True,
    entry_points={
        'console_scripts': [
            'consul-kube=consul_kube.commands:main'
        ]
    },
    python_requires='~=3.6',
    install_requires=['kubernetes', 'urllib3', 'click', 'cryptography', 'pyOpenSSL', 'jsonpath-ng'],
    setup_requires=['flake8', 'wheel', 'setuptools_scm'],
)
