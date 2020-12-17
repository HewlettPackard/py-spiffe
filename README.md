# py-spiffe Library

## Overview
Initial work in progress to create a python library for SPIFFE.

## RFC

The _RFC - Py-Spiffe features and use cases_ document is public at: https://docs.google.com/document/d/1IByE9Ge1MTyWD7rL9o99-1c5Fn83p1ra3eApARY9X-I/edit#heading=h.70d940e8vk81

## Initial contributors
* Glaucimar Aguiar (HPE)
* Gomez Coronel Andres (HPE)
* Lambrecht Max (HPE)


## Development setup

### Prerequisites
For basic development you will need:

* Python 3.6
* Pipenv (https://github.com/pypa/pipenv)
* Pyenv (https://github.com/pyenv/pyenv)

### Setup the environment

Use `pyenv` to install the different version of Python.
Python 3.6 is required for development and the other versions are required for testing.
```
pyenv install 3.6.x
pyenv install 3.7.x
pyenv install 3.8.x
pyenv install 3.9.x
```

Clone the repository
```
git clone git@github.com:HewlettPackard/py-spiffe.git
```

cd to the py-spiffe directory
```
cd py-spiffe
```

Use the installed versions to define the specific versions for development and testing
```
pyenv local 3.6.12 3.7.0 3.8.0 3.9.0
```

Create the virtual environment
```
make env
```
`.venv` directory is created using `pipenv` on the root directory of the repo.


Then install all the `dev` dependencies
```
make dev
```

Run the tests
```
make test
```

### Clean up your dev environment

To remove the virtual environment
```
make rm_env
```

