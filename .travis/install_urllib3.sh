#!/bin/bash

set -e
set -x

git clone https://github.com/shazow/urllib3.git
pip install ./urllib3[socks]
