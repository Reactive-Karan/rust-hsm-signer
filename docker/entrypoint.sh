#!/bin/sh
# Container entrypoint.
#
#   serve (default)  1. resolve the user/SO PINs (files preferred: Docker secrets)
#                       generating random ones on first start if none were given;
#                    2. initialize the SoftHSM token on first start (idempotent);
#                    3. exec the service, which provisions any missing keys.
#   anything else    exec'd as-is (e.g. `loadgen ...`, `hsm-signer keys`).
#
# PIN values are never printed or passed on a command line.
set -eu

DATA_DIR="${HSM_DATA_DIR:-/data}"

random_pin() {
    # 24 random bytes, hex encoded.
    od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}

# ensure_pin <FILE_VAR> <VALUE_VAR> <default file> <description>
ensure_pin() {
    file_var=$1 value_var=$2 default_file=$3 what=$4
    eval "file_val=\${$file_var:-}"
    eval "value_val=\${$value_var:-}"
    if [ -n "$file_val" ] || [ -n "$value_val" ]; then
        return 0
    fi
    if [ ! -s "$default_file" ]; then
        (umask 077 && random_pin > "$default_file")
        echo "entrypoint: no $what provided; generated a random one in $default_file (mode 0600, value not shown)" >&2
    fi
    export "$file_var=$default_file"
}

if [ "$#" -eq 0 ] || [ "$1" = "serve" ]; then
    [ "$#" -gt 0 ] && shift
    umask 077
    mkdir -p "$DATA_DIR/tokens"
    ensure_pin HSM_PIN_FILE HSM_PIN "$DATA_DIR/user.pin" "user PIN"
    ensure_pin HSM_SO_PIN_FILE HSM_SO_PIN "$DATA_DIR/so.pin" "SO PIN"
    hsm-signer init-token
    exec hsm-signer serve --provision "$@"
fi

exec "$@"
