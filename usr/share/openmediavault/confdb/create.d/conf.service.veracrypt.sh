#!/bin/sh

set -e

# Output the default configuration JSON matching conf.service.veracrypt.json datamodel
cat <<EOF
{
  "enable": false,
  "profiles": {
    "profile": []
  }
}
EOF

exit 0
