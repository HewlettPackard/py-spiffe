from setuptools import setup, find_packages
from codecs import open
from os import path, environ
from json import load

DESCRIPTION = 'Python library for SPIFFE'

# https://stackoverflow.com/questions/49496994/how-do-i-sync-values-in-setup-py-install-requires-with-pipfile-packages
def locked_requirements(section):
    # Explicitly adding an absolute path to PWD looks odd, but there's some
    # directory shenangians that happen without it
    with open(path.join(environ['PWD'], 'Pipfile.lock')) as pip_file:
        pipfile_json = load(pip_file)

    if section not in pipfile_json:
        print("{0} section missing from Pipfile.lock".format(section))
        return []

    return [
        package + detail.get('version', "")
        for package, detail in pipfile_json[section].items()
    ]


here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
try:
    with open(path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = DESCRIPTION

setup(
    name='pyspiffe',
    version='0.0.1',
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/spiffe/py-spiffe',
    author='HPE',
    author_email='security@spiffe.io',
    license='Apache License Version 2.0',
    packages=find_packages(where='src', exclude=['test']),
    package_dir={'': 'src'},
    install_requires=locked_requirements('default'),
    python_requires='>=3.6',
)
