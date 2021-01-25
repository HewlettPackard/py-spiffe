# py-spiffe Library

[![Build Status](https://travis-ci.com/HewlettPackard/py-spiffe.svg?branch=master)](https://travis-ci.com/HewlettPackard/py-spiffe)

## Overview
Initial work in progress to create a python library for SPIFFE.

## RFC

The _RFC - Py-Spiffe features and use cases_ document is public at: https://docs.google.com/document/d/1IByE9Ge1MTyWD7rL9o99-1c5Fn83p1ra3eApARY9X-I/edit#heading=h.70d940e8vk81

## Initial contributors
* Andres Gomez Coronel (HPE)
* Glaucimar Aguiar (HPE)
* Maximiliano Churichi (HPE)
* Max Lambrecht (HPE)
* Scott Emmons (HPE)


## Contributing
1. Fork it (https://github.com/HewlettPackard/py-spiffe/fork)
2. Clone your forked repository (git clone git@github.com:<your_github_account>/py-spiffe.git)
3. Create your feature branch (git checkout -b feature/fooBar)
4. Commit your changes (git commit -m 'Add some fooBar' --signoff)
5. Push to the branch (git push origin feature/fooBar)
6. Create a new Pull Request

## Development setup

### Prerequisites
For basic development you will need:

* Python 3.6
* Pipenv (https://github.com/pypa/pipenv)
* Pyenv (https://github.com/pyenv/pyenv)

### Setup the environment
1. Use `pyenv` to install the different version of Python.
Python 3.6 is required for development and the other versions are required for testing.
```
pyenv install 3.6.x
pyenv install 3.7.x
pyenv install 3.8.x
pyenv install 3.9.x
```

2. Clone the repository
Follow steps 1 and 2 from the [Contributing](#contributing) section.  
  
3. cd to the py-spiffe directory
```
cd py-spiffe
```

4. Use the installed versions to define the specific versions for development and testing
```
pyenv local 3.6.12 3.7.0 3.8.0 3.9.0
```

5. Create the virtual environment
```
make env
```
`.venv` directory is created using `pipenv` on the root directory of the repo.

6. Install all the `dev` dependencies
```
make dev
``` 

7. Run the tests
```
make test
```

### Clean up your dev environment
To remove the virtual environment
```
make rm_env
```

### Regenerate the protobuf code

In case the protobuf definition `workload.proto` should change, regenerate the python code running:

```
make pb_generate
```

Then amend in `workload_pb2_grpc.py` the import line replacing it by:

```
from . import workload_pb2 as workload__pb2
```

### Troubleshooting
Ubuntu 20.04 users might experience issues when creating the environment (running `make env`) due to an older version of `setuptools` installed on the virtual environment.
To work around this issue, update the version of `pipenv` to `2020.11.4` or newer.
```
pip install --upgrade --user pipenv
```

### Code style guide
The project follows the Google-style (https://google.github.io/styleguide/pyguide.html)
