# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2025 Philipp Wolfer
# Copyright (C) 2025 Laurent Monin
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

import json
import os
from pathlib import Path
import secrets
import time

from picard import log

import jwt


class TokenAuth:
    """JWT token authentication for browser integration."""

    def __init__(self, token_file: str):
        self.token_file = Path(token_file)
        self.secret = None
        self.token = None

    def initialize(self) -> str:
        """Generate secret and token, save to file.

        Returns:
            JWT token string
        """
        self.secret = secrets.token_urlsafe(32)
        payload = {
            'iat': int(time.time()),
            'pid': os.getpid(),
        }
        self.token = jwt.encode(payload, self.secret, algorithm='HS256')

        try:
            self.token_file.parent.mkdir(parents=True, exist_ok=True)
            self.token_file.write_text(json.dumps({'secret': self.secret}))
            self.token_file.chmod(0o600)
            log.debug("Token auth initialized at %s", self.token_file)
        except Exception as e:
            log.error("Failed to write token file: %s", e)

        return self.token

    def load(self) -> bool:
        """Load secret from file.

        Returns:
            True if successful
        """
        try:
            if not self.token_file.exists():
                return False
            data = json.loads(self.token_file.read_text())
            self.secret = data.get('secret')
            return self.secret is not None
        except Exception as e:
            log.debug("Failed to load token: %s", e)
            return False

    def verify(self, token: str) -> bool:
        """Verify JWT token.

        Args:
            token: JWT token string

        Returns:
            True if valid
        """
        if not self.secret:
            return False
        try:
            jwt.decode(token, self.secret, algorithms=['HS256'])
            return True
        except jwt.InvalidTokenError:
            return False

    def cleanup(self):
        """Remove token file."""
        try:
            self.token_file.unlink(missing_ok=True)
        except Exception as e:
            log.warning("Failed to remove token file: %s", e)
