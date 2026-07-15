#!/bin/sh
# Generate a stable Android release key and the GitHub Actions secret values.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
keystore=${1:-"$script_dir/naiveproxy-release.keystore"}
secrets_file=${2:-"$script_dir/naiveproxy-release.env"}
alias=${ANDROID_KEY_ALIAS:-naiveproxy}
store_password=${ANDROID_KEYSTORE_PASSWORD:-$(openssl rand -base64 36 | tr -d '\n' | tr '/+' 'ab')}
key_password=${ANDROID_KEY_PASSWORD:-$store_password}

umask 077
test ! -e "$keystore" || { echo "refusing to overwrite $keystore" >&2; exit 1; }
if command -v keytool >/dev/null 2>&1 && keytool -help >/dev/null 2>&1; then
  keytool -genkeypair -v \
    -keystore "$keystore" \
    -storetype PKCS12 \
    -storepass "$store_password" \
    -alias "$alias" \
    -keypass "$key_password" \
    -keyalg RSA -keysize 4096 -validity 10000 \
    -dname 'CN=NaiveProxy, OU=Release, O=NaiveProxy, L=Internet, ST=Internet, C=ZZ'
else
  private_key=$(mktemp)
  certificate=$(mktemp)
  trap 'rm -f "$private_key" "$certificate"' EXIT
  openssl req -x509 -newkey rsa:4096 -nodes -days 10000 \
    -keyout "$private_key" -out "$certificate" \
    -subj '/CN=NaiveProxy/OU=Release/O=NaiveProxy/L=Internet/ST=Internet/C=ZZ'
  openssl pkcs12 -export -name "$alias" \
    -inkey "$private_key" -in "$certificate" \
    -out "$keystore" -passout "pass:$store_password"
fi

cat > "$secrets_file" <<EOF
ANDROID_KEYSTORE_BASE64=$(base64 < "$keystore" | tr -d '\n')
ANDROID_KEY_ALIAS=$alias
ANDROID_KEYSTORE_PASSWORD=$store_password
ANDROID_KEY_PASSWORD=$key_password
EOF
chmod 600 "$keystore" "$secrets_file"
echo "Created $keystore and $secrets_file. Add the four values in the .env file as repository Actions secrets."
