Manual Release Process
======================

 1. Commit all changed files.
 
 2. Tag the release, making sure to use a semver.
 
        $ git tag -a v1.0.1 -m "Added support for Envoy proxy certs"

    Confirm that setuptools has picked up the git tag by running:
    
        $ python setup.py --version
        1.0.1

 3. Build using setuptools:
 
        $ python setup.py sdist bdist_wheel
        
 4. Sign and upload to test warehouse with Twine:
 
        $ twine upload -s -i <GPG_IDENTITY> -u <PYPI_USERNAME> --repository-url https://test.pypi.org/legacy/ dist/* 

 5. Push changes to Github, including the semver tag:
 
        $ git push --tags
``