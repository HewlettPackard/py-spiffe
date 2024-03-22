"""
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

import os

FORBIDDEN_FILES = ["__init__.py"]
FORBIDDEN_DIRECTORIES = ["proto"]
COPYRIGHT_TEXT = """\"\"\"
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
\"\"\"\n\n"""


def add_copyright(file_path: str, file_content: str) -> None:
    """Add copyright text to a file."""
    with open(file_path, "w") as file:
        file.write(COPYRIGHT_TEXT + file_content)


def find_and_process_py_files(path: str) -> None:
    """Find Python files and add copyright information if missing."""
    for root, dirs, files in os.walk(path, topdown=True):
        dirs[:] = [d for d in dirs if d not in FORBIDDEN_DIRECTORIES]

        for name in files:
            if name.endswith(".py") and name not in FORBIDDEN_FILES:
                file_path = os.path.join(root, name)

                with open(file_path, "r") as file:
                    file_content = file.read()

                if not file_content.startswith('"""\n(C) Copyright 2021'):
                    print(f"Adding copyright to: {file_path}")
                    add_copyright(file_path, file_content)


if __name__ == "__main__":
    directory_to_scan = os.getcwd()
    find_and_process_py_files(directory_to_scan)
