# Contributor Guidelines

## Contributing

1. [Fork this repository](https://github.com/HewlettPackard/py-spiffe/fork).
2. Clone your forked repository (`git clone git@github.com:<your_github_account>/py-spiffe.git`).
3. Create your feature branch (`git checkout -b feature/fooBar`).
4. Commit your changes (`git commit -am 'Add some fooBar' --signoff`).
5. Push to the branch (`git push origin feature/fooBar`).
6. Create a new Pull Request.

## Development Setup

### Prerequisites

Before you begin, ensure you have the following installed:

- Python 3.9 or higher.
- Poetry: [Installation instructions](https://python-poetry.org/docs/#installation).

### Running Tests, Linting, and Building

After cloning the repository and navigating to the project directory, you can use the following commands to set up your
development environment and start contributing:

- **Install Project Dependencies**:
    ```sh
    make deps
    ```

- **Run Tests**:
  To run all tests, use:
    ```sh
    make test
    ```

- **Linting**:
  To check the code style and lint the project, use:
    ```sh
    make lint
    ```

- **Format Code**:
  To automatically format the code according to the project's coding standards, use:
    ```sh
    make format
    ```

- **Build the Project**:
  To build the project (if applicable, e.g., creating a distributable package), use:
    ```sh
    make build
    ```

These commands leverage `make` targets defined in the project's `Makefile`, which in turn use Poetry to manage
dependencies.

### Regenerate the Protobuf Code

If changes are made to the protobuf definition `workload.proto`, regenerate the Python code by running:

```sh
make compile-proto
```

Amend `workload_pb2_grpc.py` by replacing the import line with:

```python
from . import workload_pb2 as workload__pb2
```

## Conventions

The project follows the Google Python Style
Guide ([https://google.github.io/styleguide/pyguide.html](https://google.github.io/styleguide/pyguide.html)).

### Docstrings

- **Modules**: Modules should include a docstring with a description of the module itself.

- **Classes**: Class docstrings should document the list of class public members, including their types.

- **Functions**: Functions should include PEP 484 type annotations for their arguments rather than describing the types
  in the docstring itself.
