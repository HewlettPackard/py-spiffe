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

"""
This module defines SpiffeId validation errors.
"""

EMPTY = 'SPIFFE ID cannot be empty.'
MISSING_TRUST_DOMAIN = 'Trust domain is missing.'
WRONG_SCHEME = 'Scheme is missing or invalid.'
BAD_TRUST_DOMAIN_CHAR = 'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.'
BAD_PATH_SEGMENT_CHAR = 'Path segment characters are limited to letters, numbers, dots, dashes, and underscores.'
DOT_SEGMENT = 'Path cannot contain dot segments.'
EMPTY_SEGMENT = 'Path cannot contain empty segments.'
TRAILING_SLASH = 'Path cannot have a trailing slash.'
