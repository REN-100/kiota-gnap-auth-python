"""
Logging configuration for kiota-gnap-auth.

Sets up a library-level logger with NullHandler as the default,
following Python logging best practices for libraries.
Applications can configure logging by attaching handlers to
the ``kiota_gnap_auth`` logger.

Usage::

    import logging
    logging.basicConfig(level=logging.DEBUG)
    # or
    logger = logging.getLogger("kiota_gnap_auth")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
"""

import logging

# Root library logger — applications attach handlers to this
_logger = logging.getLogger("kiota_gnap_auth")
_logger.addHandler(logging.NullHandler())
