# Contributing

Welcome, and thank you for your interest in contributing to our project!  Below, you'll find step-by-step instructions
to prepare your development environment and guide you through submitting your contributions effectively.

## Development Setup

### Prerequisites

Before starting, please make sure you have the following installed:

- **Python 3.9 or higher**: Check your Python version with `python --version`.
- **Poetry**: For managing dependencies and
  packaging. [Follow the installation instructions here](https://python-poetry.org/docs/#installation).

### Setting Up Your Development Environment

1. **Install pre-commit**: This tool ensures your contributions meet our code quality standards.
   ```
   pip install pre-commit
   pre-commit install
   ```

2. **Install Project Dependencies**: Navigate to the project directory and run:
    ```sh
    make deps
    ```

3. **Run Tests**: Ensure your changes don't break anything:
    ```sh
    make test
    ```

4. **Check Code Style (Linting)**: To ensure your code complies with our style guide:
    ```sh
    make lint
    ```

5. **Format Code**: Automatically format your code to match our project's coding standards:
    ```sh
    make format
    ```

6. **Build the Project**: If applicable, like creating a distributable package, use:
    ```sh
    make build
    ```

### Additional Steps

- **Regenerate Protobuf Code**: If you modify `workload.proto`, regenerate the Python code:
    ```sh
    make compile-proto
    ```
  Then, amend `workload_pb2_grpc.py` by adjusting the import line:
    ```python
    from . import workload_pb2 as workload__pb2
    ```

## How to Contribute

1. **Fork the repository**: Start by forking the repository to your GitHub account.
2. **Clone your fork**: Clone the repository to your local machine.
   ```
   git clone git@github.com:<your_github_account>/py-spiffe.git
   ```
3. **Create a feature branch**: Make changes in a new branch.
   ```
   git checkout -b feature/fooBar
   ```
4. **Make your changes**: Add your contribution.
5. **Commit your changes**: Use clear, concise commit messages.
   ```
   git commit -am 'Add some fooBar' --signoff
   ```
6. **Push to your fork**: Upload your branch to GitHub.
   ```
   git push origin feature/fooBar
   ```
7. **Open a pull request**: Submit your changes for review by opening a pull request to the upstream main branch.

### Conventions

- We follow the **Google Python Style Guide** ([guide link](https://google.github.io/styleguide/pyguide.html)).
- **Docstrings** are crucial for modules, classes, and functions. Include PEP 484 type annotations in function
  signatures rather than in docstrings.
