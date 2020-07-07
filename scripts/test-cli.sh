#!/bin/bash

# =================================================================
#
# Work of the U.S. Department of Defense, Defense Digital Service.
# Released as open source under the MIT License.  See LICENSE file.
#
# =================================================================

set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export testdata_local="${DIR}/../testdata"

export temp="${DIR}/../temp"

_testServe() {
  local accessPolicy=$1
  local expected=''
  local output=$("${DIR}/../bin/iceberg" serve --access-policy $accessPolicy --access-policy-format json --client-ca "${temp}/ca.crt" --client-ca-format pem  --root "${testdata_local}/public" --server-cert "${temp}/server.crt" --server-key "${temp}/server.key" --template "${testdata_local}/template.html" --dry-run 2>&1)
  assertEquals "unexpected output" "${expected}" "${output}"
}

testServe() {
  _testServe "${testdata_local}/access_policies/allow_all.json"
}

oneTimeSetUp() {
  echo "Using temporary directory at ${SHUNIT_TMPDIR}"
  echo "Reading testdata from ${testdata_local}"
}

oneTimeTearDown() {
  echo "Tearing Down"
}

# Load shUnit2.
. "${DIR}/shunit2"
