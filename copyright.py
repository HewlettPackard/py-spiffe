""""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

""""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from multiprocessing import Process
import os


processes = []
FORBIDDEN_FILES = ["__init__.py"]
FORBIDDEN_DIRECTORIES = ["proto"]
COPYRIGHT_TEXT = """(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

"""
Add copyright notices to .py files:

Usage:
  python copyright.py
"""


def add_copyright(file_path: str, file_content: str) -> None:
    """Add copyright text to a file."""
    file_content_with_copyright = f'""""\n{COPYRIGHT_TEXT}"""\n\n{file_content}'

    with open(file_path, "w") as file:
        file.write(file_content_with_copyright)


def verify_copyright(file_path: str) -> None:
    """Verify if a file has copyright information and add if missing."""
    with open(file_path, "r") as file:
        file_content = file.read()

    if not file_content.startswith('"""\n(C) Copyright 2021 Hewlett Packard'):
        add_copyright(file_path, file_content)


def find_py_files(path: str) -> None:
    """Recursively find Python files and verify if it has copyright information."""
    for file in os.listdir(path):
        file_path = os.path.join(path, file)

        if os.path.isdir(file_path):
            if file.startswith(".") or file in FORBIDDEN_DIRECTORIES:
                continue

            proc = Process(target=find_py_files, args=(file_path,))
            processes.append(proc)
            proc.start()

        if file in FORBIDDEN_FILES:
            continue

        elif file.endswith(".py"):
            verify_copyright(file_path)


if __name__ == "__main__":
    find_py_files(os.getcwd())

    for process in processes:
        process.join()
