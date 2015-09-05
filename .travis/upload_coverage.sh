#!/bin/bash

set -e
set -x

NO_COVERAGE_TOXENVS=(pypy docs check-manifest pypi-readme flake8 pyroma)
if ! [[ "${NO_COVERAGE_TOXENVS[*]}" =~ "${TOXENV}" ]]; then
    source ~/.venv/bin/activate
    bash <(curl -s https://codecov.io/bash) -e TRAVIS_OS_NAME,TOXENV,OPENSSL
fi
