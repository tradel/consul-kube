from setuptools import setup

setup(
    use_scm_version=True,
    entry_points={
        'console_scripts': [
            'consul-kube=main:script_entry'
        ]
    },
    python_requires='~=3.4',
    install_requires=['kubernetes', 'urllib3', 'click', 'cryptography', 'pyOpenSSL', 'jsonpath-ng'],
    setup_requires=['flake8', 'wheel', 'setuptools_scm'],
)
