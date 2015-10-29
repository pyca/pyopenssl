# -*- coding: utf-8 -*-

# Copyright 2001 Martin Sjögren and pyOpenSSL contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Stress tester for thread-related bugs in RSA and DSA key generation.  0.12 and
older held the GIL during these operations.  Subsequent versions release it
during them.
"""

from threading import Thread

from OpenSSL.crypto import TYPE_RSA, TYPE_DSA, PKey

def generate_rsa():
    keys = []
    for i in range(100):
        key = PKey()
        key.generate_key(TYPE_RSA, 1024)
        keys.append(key)

def generate_dsa():
    keys = []
    for i in range(100):
        key = PKey()
        key.generate_key(TYPE_DSA, 512)
        keys.append(key)


def main():
    threads = []
    for i in range(3):
        t = Thread(target=generate_rsa, args=())
        threads.append(t)
        t = Thread(target=generate_dsa, args=())
        threads.append(t)

    for t in threads:
        t.start()

main()
