# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
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

"""CLI communication helper for interacting with running Picard instances."""

from typing import Optional
from urllib.error import URLError
from urllib.request import urlopen

from picard import log
from picard.util.instanceinfo import (
    InstanceInfo,
    get_instance_info_path,
)


class CLIComm:
    """Helper for CLI to communicate with running Picard instance."""

    def __init__(self, pipe_path: str):
        """Initialize CLI communication.

        Args:
            pipe_path: Path to the pipe file (used to derive instance info path)
        """
        self.pipe_path = pipe_path
        self.info_path = get_instance_info_path(pipe_path)
        self.instance_info = InstanceInfo(self.info_path)

    def detect_instance(self) -> Optional[dict]:
        """Detect running Picard instance.

        Returns:
            Instance info dict if running, None otherwise
        """
        return self.instance_info.read()

    def get_http_url(self, endpoint: str = '') -> Optional[str]:
        """Get HTTP API URL if available.

        Args:
            endpoint: API endpoint path (e.g., '/api/plugins')

        Returns:
            Full URL if HTTP server is running, None otherwise
        """
        info = self.detect_instance()
        if not info or 'http' not in info:
            return None

        http_info = info['http']
        host = http_info.get('host', '127.0.0.1')
        port = http_info.get('port')

        if not port:
            return None

        return f"http://{host}:{port}{endpoint}"

    def http_get(self, endpoint: str) -> Optional[dict]:
        """Make HTTP GET request to running instance.

        Args:
            endpoint: API endpoint path (e.g., '/api/plugins')

        Returns:
            JSON response as dict, or None if request failed
        """
        url = self.get_http_url(endpoint)
        if not url:
            log.debug("No HTTP server available")
            return None

        try:
            import json

            with urlopen(url, timeout=5) as response:
                return json.loads(response.read().decode())
        except URLError as e:
            log.debug("HTTP request failed: %s", e)
            return None
        except Exception as e:
            log.error("Unexpected error in HTTP request: %s", e)
            return None

    def get_plugins(self) -> Optional[list]:
        """Get list of plugins from running instance.

        Returns:
            List of plugin dicts, or None if not available
        """
        result = self.http_get('/api/v1/plugins')
        if result:
            return result.get('plugins')
        return None

    def get_status(self) -> Optional[dict]:
        """Get status from running instance.

        Returns:
            Status dict, or None if not available
        """
        return self.http_get('/api/v1/status')
