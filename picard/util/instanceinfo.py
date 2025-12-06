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

"""Instance information file management for detecting and communicating with running Picard instances."""

import json
import os
from pathlib import Path
import time
from typing import Optional

from picard import log
from picard.const.sys import IS_WIN


def get_instance_info_path(pipe_path: str) -> str:
    """Get instance info file path from pipe path.

    Args:
        pipe_path: Path to the pipe file

    Returns:
        Path to the instance info file
    """
    return pipe_path.replace('_pipe_file', '_info.json')


class InstanceInfo:
    """Manages instance information file for inter-process communication."""

    def __init__(self, info_path: str):
        """Initialize instance info manager.

        Args:
            info_path: Path where the info file should be created
        """
        self.info_path = Path(info_path)
        self.pid = os.getpid()

    def write(
        self,
        instance_type: str = "gui",
        http_port: Optional[int] = None,
        http_host: str = "127.0.0.1",
    ) -> bool:
        """Write instance information to file.

        Args:
            instance_type: Type of instance ("gui" or "cli")
            http_port: HTTP server port if enabled
            http_host: HTTP server host if enabled

        Returns:
            True if successful, False otherwise
        """
        info = {
            "pid": self.pid,
            "type": instance_type,
            "start_time": time.time(),
        }

        if http_port:
            info["http"] = {"host": http_host, "port": http_port}

        try:
            self.info_path.parent.mkdir(parents=True, exist_ok=True)
            self.info_path.write_text(json.dumps(info, indent=2))
            log.debug("Instance info written to %s", self.info_path)
            return True
        except Exception as e:
            log.warning("Failed to write instance info: %s", e)
            return False

    def read(self) -> Optional[dict]:
        """Read instance information from file.

        Returns:
            Dictionary with instance info, or None if not available
        """
        try:
            if not self.info_path.exists():
                return None

            data = json.loads(self.info_path.read_text())

            # Verify the process is still running
            if not self._is_process_running(data.get("pid")):
                log.debug("Stale instance info found, removing")
                self.remove()
                return None

            return data
        except Exception as e:
            log.debug("Failed to read instance info: %s", e)
            return None

    def remove(self) -> None:
        """Remove instance information file."""
        try:
            self.info_path.unlink(missing_ok=True)
            log.debug("Instance info removed from %s", self.info_path)
        except Exception as e:
            log.warning("Failed to remove instance info: %s", e)

    @staticmethod
    def _is_process_running(pid: Optional[int]) -> bool:
        """Check if a process with given PID is running.

        Args:
            pid: Process ID to check

        Returns:
            True if process is running, False otherwise
        """
        if pid is None:
            return False

        try:
            if IS_WIN:
                import ctypes

                kernel32 = ctypes.windll.kernel32
                PROCESS_QUERY_INFORMATION = 0x0400
                handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
                if handle:
                    kernel32.CloseHandle(handle)
                    return True
                return False
            else:
                # On Unix, sending signal 0 checks if process exists
                os.kill(pid, 0)
                return True
        except (OSError, AttributeError):
            return False
