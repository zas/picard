# -*- coding: utf-8 -*-


# Slugify function copied and modified from
# https://github.com/django/django/blob/e3d0b4d5501c6d0bc39f035e4345e5bdfde12e41/django/utils/text.py#L394-L406
# 
# Copyright (c) Django Software Foundation and individual contributors.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#     1. Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#
#     3. Neither the name of Django nor the names of its contributors may be used
#        to endorse or promote products derived from this software without
#        specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import re
import unicodedata


def slugify(value, allow_unicode=False):
    """
    Convert to ASCII if 'allow_unicode' is False. Convert spaces to underscores.
    Replace characters that aren't alphanumerics, underscores, or hyphens by hyphens.
    Also strip leading and trailing whitespace.

    Based on https://stackoverflow.com/a/295466
    And https://github.com/django/django/blob/master/django/utils/text.py

    >>> slugify("  l-$à__bs/K  ⺶t\\u³  ")
    'l-a_bs-K_t-u3'
    >>> slugify("  l-$à__bs/K  ⺶t\\u³  ", allow_unicode=True)
    'l-à_bs-K_-t-u3'
    """
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize('NFKC', value).strip()
    else:
        value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii').strip()
    value = re.sub(r'\s+', '_', value)
    value = re.sub(r'[^\w]', '-', value)
    value = re.sub(r'-+', '-', value)
    return re.sub(r'_+', '_', value)
