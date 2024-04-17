# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import string
import secrets
import logging

logger = logging.getLogger("integration_test.py")
logger.setLevel(logging.INFO)
log_handler = logging.StreamHandler()
log_formatter = logging.Formatter("%(levelname)s: %(message)s")
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)


def random_string(n):
    return "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(n)
    )
