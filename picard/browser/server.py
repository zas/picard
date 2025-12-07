# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2006-2007, 2011 Lukáš Lalinský
# Copyright (C) 2011-2013 Michael Wiencek
# Copyright (C) 2012 Chad Wilson
# Copyright (C) 2012-2013, 2018, 2021-2022, 2024-2025 Philipp Wolfer
# Copyright (C) 2013, 2018, 2020-2021, 2024 Laurent Monin
# Copyright (C) 2016 Suhas
# Copyright (C) 2016-2017 Sambhav Kothari
# Copyright (C) 2018 Vishal Choudhary
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


from http.server import (
    BaseHTTPRequestHandler,
    HTTPServer,
)
from itertools import chain
import json
import os
import re
import threading
from urllib.parse import (
    parse_qs,
    urlparse,
)

from PyQt6 import QtCore

from picard import (
    PICARD_APP_NAME,
    PICARD_ORG_NAME,
    PICARD_VERSION_STR,
    log,
)
from picard.browser import addrelease
from picard.browser.auth import TokenAuth
from picard.config import get_config
from picard.const import BROWSER_INTEGRATION_LOCALIP
from picard.oauth import OAuthInvalidStateError
from picard.util import mbid_validate
from picard.util.thread import to_main


try:
    from http.server import ThreadingHTTPServer as OurHTTPServer
except ImportError:
    from socketserver import ThreadingMixIn

    class OurHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True


SERVER_VERSION = '%s-%s/%s' % (PICARD_ORG_NAME, PICARD_APP_NAME, PICARD_VERSION_STR)
RE_VALID_ORIGINS = re.compile(r'^(?:[^\.]+\.)*musicbrainz\.org$')
LOG_PREFIX = "Browser Integration"


def _is_valid_origin(origin):
    try:
        url = urlparse(origin)
    except ValueError:
        return False
    hostname = url.hostname
    if not hostname:
        return False
    if RE_VALID_ORIGINS.match(hostname):
        return True
    config = get_config()
    return config.setting['server_host'] == hostname


class BrowserIntegration(QtCore.QObject):
    listen_port_changed = QtCore.pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.server = None
        self.token_auth = None

    @property
    def host_address(self):
        if not self.server:
            return ''
        return self.server.server_address[0]

    @property
    def port(self):
        if not self.server:
            return 0
        return self.server.server_address[1]

    @property
    def is_running(self):
        return self.server is not None

    def start(self):
        if self.server:
            self.stop()

        config = get_config()

        LISTEN_ALL = '0.0.0.0'
        MIN_PORT = config.setting["browser_integration_port"]
        MAX_PORT = 65535

        if config.setting["browser_integration_localhost_only"]:
            host_address = BROWSER_INTEGRATION_LOCALIP
        else:
            host_address = LISTEN_ALL

        # Initialize token auth
        from picard.const import USER_DIR

        token_file = os.path.join(USER_DIR, 'browser_token.json')
        self.token_auth = TokenAuth(token_file)
        self.token_auth.initialize()

        try:
            for port in range(MIN_PORT, MAX_PORT):
                try:
                    self.server = OurHTTPServer((host_address, port), RequestHandler)
                    self.server.token_auth = self.token_auth
                except OSError:
                    continue
                log.info("%s: Starting, listening on address %s and port %d", LOG_PREFIX, host_address, port)
                self.listen_port_changed.emit(port)
                threading.Thread(target=self.server.serve_forever).start()
                break
            else:
                log.error(
                    "%s: Failed to find an available port in range %s-%s on address %s",
                    LOG_PREFIX,
                    MIN_PORT,
                    MAX_PORT,
                    host_address,
                )
                self.stop()
        except Exception:
            log.error("%s: Failed to start listening on %s", LOG_PREFIX, host_address, exc_info=True)

    def stop(self):
        if self.server:
            try:
                log.info("%s: Stopping", LOG_PREFIX)
                self.server.shutdown()
                self.server.server_close()
                self.server = None
                self.listen_port_changed.emit(self.port)
            except Exception:
                log.error("%s: Failed to stop", LOG_PREFIX, exc_info=True)
        else:
            log.debug("%s: inactive, no need to stop", LOG_PREFIX)

        if self.token_auth:
            self.token_auth.cleanup()
            self.token_auth = None


# From https://github.com/python/cpython/blob/f474264b1e3cd225b45cf2c0a91226d2a9d3ee9b/Lib/http/server.py#L570C1-L573C43
# https://en.wikipedia.org/wiki/List_of_Unicode_characters#Control_codes
CONTROL_CHAR_TABLE = str.maketrans({c: rf'\x{c:02x}' for c in chain(range(0x20), range(0x7F, 0xA0))})
CONTROL_CHAR_TABLE[ord('\\')] = r'\\'


def safe_message(message):
    return message.translate(CONTROL_CHAR_TABLE)


class RequestHandler(BaseHTTPRequestHandler):
    def _check_auth(self):
        """Check JWT token authentication.

        Returns:
            True if authenticated, False otherwise
        """
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return False

        token = auth_header[7:]  # Remove 'Bearer ' prefix
        return self.server.token_auth.verify(token)

    def do_OPTIONS(self):
        origin = self.headers['origin']
        if _is_valid_origin(origin):
            self.send_response(204)
            self.send_header('Access-Control-Allow-Origin', clean_header(origin))
            self.send_header('Access-Control-Allow-Methods', 'GET')
            self.send_header('Access-Control-Allow-Credentials', 'false')
            self.send_header('Access-Control-Allow-Private-Network', 'true')
            self.send_header('Access-Control-Max-Age', 3600)
            self.send_header('Vary', 'Origin')
        else:
            self.send_response(401)
        self.end_headers()

    def do_GET(self):
        try:
            self._handle_get()
        except Exception:
            log.error('%s: failed handling request', LOG_PREFIX, exc_info=True)
            self._response(500, 'Unexpected request error')

    def do_POST(self):
        try:
            self._handle_post()
        except Exception:
            log.error('%s: failed handling request', LOG_PREFIX, exc_info=True)
            self._response(500, 'Unexpected request error')

    def _log(self, log_func, fmt, args):
        log_func(
            "%s: %s %s",
            LOG_PREFIX,
            self.address_string(),
            safe_message(fmt % args),
        )

    def log_error(self, format, *args):
        self._log(log.error, format, args)

    def log_message(self, format, *args):
        self._log(log.info, format, args)

    def _handle_get(self):
        parsed = urlparse(self.path)
        args = parse_qs(parsed.query)
        action = parsed.path

        # Public endpoints
        if action == '/':
            self._response(200, SERVER_VERSION)
            return

        # API endpoints require authentication
        if action.startswith('/api'):
            if not self._check_auth():
                self._response(401, 'Unauthorized')
                return

        if action in ('/api', '/api/', '/api/v1', '/api/v1/', '/api/v1/help'):
            self._api_help()
        elif action == '/api/v1/status':
            self._api_status()
        elif action.startswith('/api/v1/plugins/'):
            plugin_id = action[16:]  # Remove '/api/v1/plugins/' prefix
            self._api_plugin_detail(plugin_id)
        elif action == '/api/v1/plugins':
            self._api_plugins()
        elif action == '/api/v1/albums':
            self._api_albums()
        elif action == '/api/v1/files':
            self._api_files()
        elif action == '/api/v1/clusters':
            self._api_clusters()
        elif action == '/openalbum':
            self._load_mbid('album', args)
        elif action == '/opennat':
            self._load_mbid('nat', args)
        elif action == '/add' and addrelease.is_available():
            self._add_release(args)
        elif action == '/auth':
            self._auth(args)
        else:
            self._response(404, 'Unknown action.')

    def _handle_post(self):
        parsed = urlparse(self.path)
        action = parsed.path

        if action == '/api/v1/command':
            if not self._check_auth():
                self._response(401, 'Unauthorized')
                return
            self._api_command()
        else:
            self._response(404, 'Unknown action.')

    def _load_mbid(self, type, args):
        if 'id' in args and args['id']:
            mbid = args['id'][0]
            if not mbid_validate(mbid):
                self._response(400, '"id" is not a valid MBID.')
            else:
                tagger = QtCore.QCoreApplication.instance()
                to_main(tagger.load_mbid, type, mbid)
                self._response(200, 'MBID "%s" loaded' % mbid)
        else:
            self._response(400, 'Missing parameter "id".')

    def _add_release(self, args):
        if 'token' in args and args['token']:
            try:
                content = addrelease.serve_form(args['token'][0])
                self._response(200, content, 'text/html')
            except addrelease.NotFoundError as err:
                self._response(404, str(err))
            except addrelease.InvalidTokenError:
                self._response(400, 'Invalid token')
        else:
            self._response(400, 'Missing parameter "token".')

    def _auth(self, args):
        if 'code' in args and args['code']:
            tagger = QtCore.QCoreApplication.instance()
            oauth_manager = tagger.webservice.oauth_manager
            try:
                state = args.get('state', [''])[0]
                callback = oauth_manager.verify_state(state)
            except OAuthInvalidStateError:
                self._response(400, 'Invalid "state" parameter.')
                return
            to_main(
                oauth_manager.exchange_authorization_code,
                authorization_code=args['code'][0],
                scopes='profile tag rating collection submit_isrc submit_barcode',
                callback=callback,
            )
            self._response(200, "Authentication successful, you can close this window now.", 'text/html')
        else:
            self._response(400, 'Missing parameter "code".')

    def _api_status(self):
        """Return API status information as JSON."""
        status = {
            'version': PICARD_VERSION_STR,
            'server': SERVER_VERSION,
            'running': True,
        }
        self._json_response(200, status)

    def _get_tagger(self):
        """Get tagger instance.

        Returns:
            Tagger instance or None
        """
        return QtCore.QCoreApplication.instance()

    def _extract_metadata(self, obj, *keys):
        """Safely extract metadata fields from an object.

        Args:
            obj: Object with metadata attribute
            *keys: Metadata keys to extract

        Returns:
            dict: Dictionary with extracted metadata (only non-None values)
        """
        result = {}
        if not hasattr(obj, 'metadata'):
            return result

        metadata = obj.metadata
        for key in keys:
            value = metadata.get(key)
            if value:
                result[key] = value
        return result

    def _api_help(self):
        """Return API documentation as JSON."""
        # Get the actual port from the server
        port = self.server.server_address[1]
        base_url = f'http://localhost:{port}'

        help_data = {
            'api_version': '1.0',
            'base_url': base_url,
            'endpoints': {
                'GET /api': 'This help message',
                'GET /api/v1': 'This help message',
                'GET /api/v1/help': 'This help message',
                'GET /api/v1/status': 'Server version and status',
                'GET /api/v1/plugins': 'List all plugins with their state',
                'GET /api/v1/plugins/{id}': 'Get detailed information for a specific plugin (by ID or UUID)',
                'GET /api/v1/albums': 'List currently loaded albums',
                'GET /api/v1/files': 'List currently loaded files',
                'GET /api/v1/clusters': 'List file clusters and unclustered files count',
                'POST /api/v1/command': 'Execute a remote command (JSON body: {"command": "COMMAND", "args": [...]})',
            },
            'examples': {
                'Get plugin list': f'curl {base_url}/api/v1/plugins',
                'Get plugin details': f'curl {base_url}/api/v1/plugins/88a16689-663b-4d78-bc1c-2fd7698e51b0',
                'Show Picard window': f'curl -X POST {base_url}/api/v1/command -H "Content-Type: application/json" -d \'{{"command": "SHOW"}}\'',
                'Load a file': f'curl -X POST {base_url}/api/v1/command -H "Content-Type: application/json" -d \'{{"command": "LOAD", "args": ["/path/to/file.mp3"]}}\'',
            },
        }
        self._json_response(200, help_data)

    def _api_plugins(self):
        """Return list of plugins with their state as JSON."""
        tagger = self._get_tagger()

        if not hasattr(tagger, 'pluginmanager3') or not tagger.pluginmanager3:
            self._json_response(200, {'plugins': [], 'count': 0})
            return

        plugins = []
        for plugin in tagger.pluginmanager3.plugins:
            plugin_info = {
                'id': plugin.plugin_id,
                'state': plugin.state.name.lower(),
            }

            if hasattr(plugin, 'manifest') and plugin.manifest:
                plugin_info['name'] = plugin.manifest.name()
                plugin_info['uuid'] = plugin.manifest.uuid
                plugin_info['version'] = str(plugin.manifest.version)
                plugin_info['description'] = plugin.manifest.description('en')
                plugin_info['authors'] = plugin.manifest.authors

            plugins.append(plugin_info)

        self._json_response(200, {'plugins': plugins, 'count': len(plugins)})

    def _api_albums(self):
        """Return list of loaded albums as JSON."""
        tagger = self._get_tagger()

        if not hasattr(tagger, 'albums'):
            self._json_response(200, {'albums': [], 'count': 0})
            return

        albums = []
        for album_id, album in tagger.albums.items():
            album_info = {
                'id': album_id,
                'loaded': album.loaded,
            }

            # Add metadata if available
            metadata = self._extract_metadata(
                album, 'album', 'albumartist', 'date', '~releasegroup', 'musicbrainz_albumid'
            )
            if metadata.get('album'):
                album_info['title'] = metadata['album']
            if metadata.get('albumartist'):
                album_info['artist'] = metadata['albumartist']
            if metadata.get('date'):
                album_info['date'] = metadata['date']
            if metadata.get('~releasegroup'):
                album_info['release_group_id'] = metadata['~releasegroup']
            if metadata.get('musicbrainz_albumid'):
                album_info['release_id'] = metadata['musicbrainz_albumid']

            # Track count
            if hasattr(album, 'tracks'):
                album_info['track_count'] = len(album.tracks)

            albums.append(album_info)

        self._json_response(200, {'albums': albums, 'count': len(albums)})

    def _api_files(self):
        """Return list of loaded files as JSON."""
        tagger = self._get_tagger()

        if not hasattr(tagger, 'files'):
            self._json_response(200, {'files': [], 'count': 0})
            return

        files = []
        for file_id, file_obj in tagger.files.items():
            file_info = {
                'id': file_id,
                'filename': file_obj.filename,
            }

            # Add metadata if available
            metadata = self._extract_metadata(file_obj, 'title', 'artist', 'album', '~length')
            if metadata.get('title'):
                file_info['title'] = metadata['title']
            if metadata.get('artist'):
                file_info['artist'] = metadata['artist']
            if metadata.get('album'):
                file_info['album'] = metadata['album']
            if metadata.get('~length'):
                file_info['length'] = metadata['~length']

            # Parent album/track info
            if hasattr(file_obj, 'parent'):
                parent = file_obj.parent
                if parent:
                    file_info['parent_id'] = parent.id if hasattr(parent, 'id') else None

            files.append(file_info)

        self._json_response(200, {'files': files, 'count': len(files)})

    def _api_clusters(self):
        """Return list of file clusters as JSON."""
        tagger = self._get_tagger()

        if not hasattr(tagger, 'clusters'):
            self._json_response(200, {'clusters': [], 'count': 0, 'unclustered_files': 0})
            return

        clusters = []
        for cluster in tagger.clusters:
            cluster_info = {
                'id': cluster.id if hasattr(cluster, 'id') else None,
                'file_count': len(cluster.files) if hasattr(cluster, 'files') else 0,
            }

            # Add metadata if available
            metadata = self._extract_metadata(cluster, 'album', 'albumartist')
            if metadata.get('album'):
                cluster_info['album'] = metadata['album']
            if metadata.get('albumartist'):
                cluster_info['artist'] = metadata['albumartist']

            # Lookup status
            if hasattr(cluster, 'lookup_task'):
                cluster_info['lookup_in_progress'] = cluster.lookup_task is not None

            clusters.append(cluster_info)

        # Add unclustered files count
        unclustered_count = 0
        if hasattr(tagger, 'unclustered_files') and hasattr(tagger.unclustered_files, 'files'):
            unclustered_count = len(tagger.unclustered_files.files)

        self._json_response(200, {'clusters': clusters, 'count': len(clusters), 'unclustered_files': unclustered_count})

    def _api_plugin_detail(self, plugin_id):
        """Return detailed information for a specific plugin."""
        tagger = self._get_tagger()

        if not hasattr(tagger, 'pluginmanager3') or not tagger.pluginmanager3:
            self._json_response(404, {'error': 'Plugin manager not available'})
            return

        # Find plugin by ID or UUID
        plugin = None
        for p in tagger.pluginmanager3.plugins:
            if p.plugin_id == plugin_id:
                plugin = p
                break
            if hasattr(p, 'manifest') and p.manifest and p.manifest.uuid == plugin_id:
                plugin = p
                break

        if not plugin:
            self._json_response(404, {'error': f'Plugin not found: {plugin_id}'})
            return

        # Build detailed response
        detail = {
            'id': plugin.plugin_id,
            'state': plugin.state.name.lower(),
            'path': str(plugin.local_path),
        }

        if hasattr(plugin, 'manifest') and plugin.manifest:
            manifest = plugin.manifest
            detail['name'] = manifest.name()
            detail['uuid'] = manifest.uuid
            detail['version'] = str(manifest.version)
            detail['description'] = manifest.description('en')
            detail['authors'] = manifest.authors
            detail['license'] = manifest.license
            detail['license_url'] = manifest.license_url
            detail['api_versions'] = manifest.api_versions

            # Optional fields from manifest data
            if hasattr(manifest, '_data'):
                data = manifest._data
                if 'categories' in data:
                    detail['categories'] = data['categories']
                if 'homepage' in data:
                    detail['homepage'] = data['homepage']
                if 'min_python_version' in data:
                    detail['min_python_version'] = data['min_python_version']

        # Add metadata if available
        if hasattr(tagger.pluginmanager3, '_get_plugin_metadata'):
            metadata = tagger.pluginmanager3._get_plugin_metadata(detail.get('uuid'))
            if metadata:
                detail['source_url'] = metadata.url
                detail['ref'] = metadata.ref
                detail['commit'] = metadata.commit

        self._json_response(200, detail)

    def _api_command(self):
        """Execute a remote command via HTTP POST."""
        try:
            # Read and parse JSON body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self._json_response(400, {'error': 'Empty request body'})
                return

            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)

            command = data.get('command', '').upper()
            args = data.get('args', [])

            if not command:
                self._json_response(400, {'error': 'Missing command parameter'})
                return

            # Log the received command
            log.info('%s: Received API command: %s %s', LOG_PREFIX, command, args if args else '')

            # Get remote command handlers
            from picard.remotecommands import RemoteCommands

            commands = RemoteCommands.commands()

            if command not in commands:
                self._json_response(400, {'error': f'Unknown command: {command}'})
                return

            # Execute command
            handler = commands[command]
            for arg in args or ['']:
                handler(arg)

            self._json_response(200, {'status': 'success', 'command': command})

        except json.JSONDecodeError as e:
            self._json_response(400, {'error': f'Invalid JSON: {e}'})
        except Exception as e:
            log.error('%s: command execution failed', LOG_PREFIX, exc_info=True)
            self._json_response(500, {'error': f'Command execution failed: {e}'})

    def _json_response(self, code, data):
        """Send JSON response."""
        content = json.dumps(data, indent=2)
        self._response(code, content, 'application/json')

    def _response(self, code, content='', content_type='text/plain'):
        self.server_version = SERVER_VERSION
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'max-age=0')
        origin = self.headers['origin']
        if _is_valid_origin(origin):
            self.send_header('Access-Control-Allow-Origin', clean_header(origin))
            self.send_header('Vary', 'Origin')
        self.end_headers()
        self.wfile.write(content.encode())


def clean_header(header):
    return re.sub("[\r\n:]", "", header)
