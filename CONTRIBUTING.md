# Contributor guidelines

# Contributing
1. [Fork this repository](https://github.com/HewlettPackard/py-spiffe/fork)
2. Clone your forked repository (git clone git@github.com:<your_github_account>/py-spiffe.git)
3. Create your feature branch (git checkout -b feature/fooBar)
4. Commit your changes (git commit -m 'Add some fooBar' --signoff)
5. Push to the branch (git push origin feature/fooBar)
6. Create a new Pull Request

# Development setup

## Prerequisites
For basic development you will need:

* Python 3.6
* Pipenv (https://github.com/pypa/pipenv)
* Pyenv (https://github.com/pyenv/pyenv)

## Setup the environment
1. Use `pyenv` to install the different version of Python.
Python 3.6 is required for development and the other versions are required for testing.
```
pyenv install 3.6.x
pyenv install 3.7.x
pyenv install 3.8.x
pyenv install 3.9.x
```

2. Clone the repository
Follow steps 1 and 2 from the [Contributing](#Contributing) section.

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

## Clean up your dev environment
To remove the virtual environment
```
make rm_env
```

## Troubleshooting
Ubuntu 20.04 users might experience issues when creating the environment (running `make env`) due to an older version of `setuptools` installed on the virtual environment.
To work around this issue, update the version of `pipenv` to `2020.11.4` or newer.
```
pip install --upgrade --user pipenv
```

# Regenerate the protobuf code

In case the protobuf definition `workload.proto` should change, regenerate the python code running:

```
make pb_generate
```

Then amend in `workload_pb2_grpc.py` the import line replacing it by:

```
from . import workload_pb2 as workload__pb2
```

# Conventions
The project follows the Google Python Style Guide (https://google.github.io/styleguide/pyguide.html)

In addition to the conventions covered in the Google Python Style Guide, the following
conventions apply to the PySPIFFE repository:

## Docstrings
### Modules
Modules should include a docstring with a description of the module itself. Module level
variables should be documented in an inline docstring immediately following the variable.
As example this is the docstring of pyspiffe.spiffe_id.spiffe_id.py:

```
"""
This module manages SpiffeId objects.
"""

...

SPIFFE_ID_MAXIMUM_LENGTH = 2048
"""int: Maximum length for SPIFFE IDs."""

```

### Classes
Class docstrings should document the list of public members including its types.
Then `__init__` methods should be documented including its arguments. Typing for arguments
should be defined as PEP 484 type annotations. As example:

```
class ExampleClass(object):
    """The summary line for a class docstring should fit on one line.

    If the class has public attributes, they may be documented here
    in an `Attributes` section including its type information.

    Attributes:
        attr1 (str): Description of `attr1`.
        attr2 (int, optional): Description of `attr2`.
    """

    def __init__(self, param1: str, param2: bool, param3: int = None) -> None:
        """Example of docstring on the __init__ method.

        Args:
            param1: Description of `param1`.
            param2: Description of `param2`. Multiple
                lines are supported.
            param3: Description of `param3`.

        """
        self.attr1 = param1
        self.attr2 = param2
        self.attr3 = param3
```
_Note_: Do not include the `self` parameter in the ``Args`` section.

### Functions
Functions should include the type of their arguments as
[PEP 484](https://www.python.org/dev/peps/pep-0484/) type annotations and not as part
of the docstrings. As example:
```
def function_with_pep484_type_annotations(param1: int, param2: str) -> bool:
    """Example function with PEP 484 type annotations.

    Args:
        param1: The first parameter.
        param2: The second parameter.

    Returns:
        The return value. True for success, False otherwise.

    Raises:
        ValueError: If `param1` is lees than 0.

    Examples:
        >>> result = function_with_pep484_type_annotations(1, 2)
        >>> print(result)
        3

    """
    if param1 < 0:
        raise ValueError('param1 may be greater or equal to zero.')
    return param1 + param2
```

## Errors
Error messages should end with periods.

