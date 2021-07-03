"""
This module defines SpiffeId validation errors.
"""
EMPTY = 'SPIFFE ID cannot be empty.'
MISSING_TRUST_DOMAIN = 'Trust domain is missing.'
WRONG_SCHEME = 'Scheme is missing or invalid.'
BAD_TRUST_DOMAIN_CHAR = 'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.'
BAD_PATH_SEGMENT_CHAR = 'Path segment characters are limited to letters, numbers, dots, dashes, and underscores.'
DOT_SEGMENT = 'Path cannot contain dot segments.'
NO_LEADING_SLASH = 'Path must have a leading slash.'
EMPTY_SEGMENT = 'Path cannot contain empty segments.'
TRAILING_SLASH = 'Path cannot have a trailing slash.'
