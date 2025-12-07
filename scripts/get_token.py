#!/usr/bin/env python3
"""Generate JWT token from browser_token.json for testing."""

import json
import os

import jwt


token_file = os.path.expanduser('~/.config/MusicBrainz/Picard/browser_token.json')

with open(token_file) as f:
    data = json.load(f)
    secret = data['secret']

# Generate token (payload doesn't matter for verification, only secret does)
payload = {'iat': 0, 'pid': 0}
token = jwt.encode(payload, secret, algorithm='HS256')

print(token)
