## Overview

This script retrieves the wallet history by sending a wallet descriptor to the Waterfalls server.

It is designed to run in the macOS Terminal.
This helps avoid cross-platform differences in base64 encoding that can happen on Windows environments.

The script demonstrates two methods of transmitting the descriptor:

1. **Plain descriptor** — sent directly in the URL query string
2. **Encrypted descriptor** — encrypted using the server's public key (age encryption) before transmission

After executing both requests, the script compares the responses to verify that both methods return identical results.

## Script configuration
By default, the script will use an open endpoint that does not require authorization, Liquid network, with the default descriptor.

### Waterfalls endpoints for the liquid mainnet (WATERFALLS_URL)
You can use a different network by changing the `liquid` in the URL. Liquid examples:
- Base (auth isn't required): https://waterfalls.liquidwebwallet.org/liquid/api
- Blockstream Explorer Enterprise staging: https://enterprise.staging.blockstream.info/liquid/api/waterfalls
- Blockstream Explorer Enterprise: https://enterprise.blockstream.info/liquid/api

### Auth endpoints (AUTH_URL)
If you use a Blockstream Explorer Enterprise URL, this field is required, you must also specify `CLIENT_ID` and `CLIENT_SECRET` for authorization.
- Blockstream Explorer Enterprise staging: https://login.staging.blockstream.com/realms/blockstream-public/protocol/openid-connect/token
- Blockstream Explorer Enterprise: https://login.blockstream.com/realms/blockstream-public/protocol/openid-connect/token

### Descriptor (DESCRIPTOR)
If not provided, a default descriptor will be used in the script.

## Script code
```bash
#!/bin/bash
set -e

WATERFALLS_URL="${WATERFALLS_URL:-https://waterfalls.liquidwebwallet.org/liquid/api}"
DESCRIPTOR="${DESCRIPTOR:-elwpkh(xpub6BemYiVNp19a1eGXYz87DQAbhWRj1UFE3PMz5YJMcvcyneZdLz7a69zDfq4cVFjYs6dxKhsngEnuwo5mbhoMFA8iVTK45sKcmFNwzupPtVC/<0;1>/*)}"

AUTH_URL="${AUTH_URL}"
CLIENT_ID="${CLIENT_ID}"
CLIENT_SECRET="${CLIENT_SECRET}"
CLIENT_CREDENTIALS="client_credentials"
SCOPE="openid"

TOKEN=""
if [ -n "$AUTH_URL" ]; then
  echo "❗️ Auth enabled."

  TOKEN_RESPONSE=$(curl -s -X POST $AUTH_URL \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&grant_type=$CLIENT_CREDENTIALS&scope=$SCOPE")

  # Check for errors in response
  if echo "$TOKEN_RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
    ERROR_MSG=$(echo "$TOKEN_RESPONSE" | jq -r '.error_description // .error')
    echo "❌ Auth failed: '$ERROR_MSG'"
    exit 1
  fi

  TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
  
  # Verify token was extracted successfully
  if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "❌ Failed to extract access token from response"
    exit 1
  fi
  
  echo "✅ Auth token received."
fi

# URL encode the descriptor
URLENCODED_DESCRIPTOR=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$DESCRIPTOR'))")  

# Send the URL encoded descriptor to the server
RESPONSE_WITH_PLAIN_DESCRIPTOR=$(curl -sS -w $'\n%{http_code}' -H "Authorization: Bearer $TOKEN" "$WATERFALLS_URL/v2/waterfalls?descriptor=$URLENCODED_DESCRIPTOR")
RESPONSE_WITH_PLAIN_DESCRIPTOR_HTTP_CODE=${RESPONSE_WITH_PLAIN_DESCRIPTOR##*$'\n'}
RESPONSE_WITH_PLAIN_DESCRIPTOR_BODY=${RESPONSE_WITH_PLAIN_DESCRIPTOR%$'\n'*}
if [ "$RESPONSE_WITH_PLAIN_DESCRIPTOR_HTTP_CODE" = "200" ] || [ "$RESPONSE_WITH_PLAIN_DESCRIPTOR_HTTP_CODE" = "201" ]; then
  echo "✅ Response for plain urlencoded descriptor received successfully. (HTTP $RESPONSE_WITH_PLAIN_DESCRIPTOR_HTTP_CODE)"
else
  echo "❌ Failed to send plain urlencoded descriptor. (HTTP $RESPONSE_WITH_PLAIN_DESCRIPTOR_HTTP_CODE)"
  exit 1
fi


SERVER_KEY_RESPONSE=$(curl -sS -w $'\n%{http_code}' -H "Authorization: Bearer $TOKEN" "$WATERFALLS_URL/v1/server_recipient")
SERVER_KEY_HTTP_CODE=${SERVER_KEY_RESPONSE##*$'\n'}
SERVER_KEY=${SERVER_KEY_RESPONSE%$'\n'*}
if [ "$SERVER_KEY_HTTP_CODE" = "200" ] || [ "$SERVER_KEY_HTTP_CODE" = "201" ]; then
  echo "✅ Server pub key received successfully. (HTTP $SERVER_KEY_HTTP_CODE)"
else
  echo "❌ Failed to receive server key. (HTTP $SERVER_KEY_HTTP_CODE) "
  exit 1
fi

ENCRYPTED_DESCRIPTOR=$(printf '%s' "$DESCRIPTOR" \
  | age -r "$SERVER_KEY" \
  | base64 \
  | tr -d '\n=')
echo "✅ Descriptor encrypted successfully."

URLENCODED_ENCRYPTED_DESCRIPTOR=$(printf '%s' "$ENCRYPTED_DESCRIPTOR" \
  | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read()))")
echo "✅ Encrypted descriptor URL encoded successfully."

# Send the URL encoded descriptor to the server
RESPONSE_WITH_ENCODED_DESCRIPTOR=$(curl -sS -w $'\n%{http_code}' -H "Authorization: Bearer $TOKEN" "$WATERFALLS_URL/v2/waterfalls?descriptor=$URLENCODED_ENCRYPTED_DESCRIPTOR")
RESPONSE_WITH_ENCODED_DESCRIPTOR_HTTP_CODE=${RESPONSE_WITH_ENCODED_DESCRIPTOR##*$'\n'}
RESPONSE_WITH_ENCODED_DESCRIPTOR_BODY=${RESPONSE_WITH_ENCODED_DESCRIPTOR%$'\n'*}
if [ "$RESPONSE_WITH_ENCODED_DESCRIPTOR_HTTP_CODE" = "200" ] || [ "$RESPONSE_WITH_ENCODED_DESCRIPTOR_HTTP_CODE" = "201" ]; then
  echo "✅ Response for encrypted urlencoded descriptor received successfully. (HTTP $RESPONSE_WITH_ENCODED_DESCRIPTOR_HTTP_CODE)"
else
  echo "❌ Failed to send encrypted urlencoded descriptor. (HTTP $RESPONSE_WITH_ENCODED_DESCRIPTOR_HTTP_CODE)"
  exit 1
fi

if [ "$RESPONSE_WITH_ENCODED_DESCRIPTOR_BODY" = "$RESPONSE_WITH_PLAIN_DESCRIPTOR_BODY" ]; then
  echo "✅ Response bodies are the same for both plain and encrypted descriptors."
else
  echo "❌ Response bodies are different for plain and encrypted descriptors."
  exit 1
fi

echo $RESPONSE_WITH_PLAIN_DESCRIPTOR_BODY | jq
```

## Example usage
1. Copy the script code and make it executable, name it `waterfall.sh`:

2. Run one of the following commands depending on the desired configuration:
- Run with base waterfall URL without auth:
  ```bash
  ./waterfall.sh
  ```
- Run with Blockstream Explorer Enterprise staging waterfall URL and auth, fill in the `CLIENT_ID` and `CLIENT_SECRET` with the appropriate values:
  ```bash
  WATERFALLS_URL=https://enterprise.staging.blockstream.info/liquid/api/waterfalls \
  AUTH_URL=https://login.staging.blockstream.com/realms/blockstream-public/protocol/openid-connect/token \
  CLIENT_ID= \
  CLIENT_SECRET= \
  ./waterfall.sh
  ```
- Run with Blockstream Explorer Enterprise waterfall URL and auth, fill in the `CLIENT_ID` and `CLIENT_SECRET` with the appropriate values:
  ```bash
  WATERFALLS_URL=https://enterprise.blockstream.info/liquid/api/waterfalls \
  AUTH_URL=https://login.blockstream.com/realms/blockstream-public/protocol/openid-connect/token \
  CLIENT_ID= \
  CLIENT_SECRET= \
  ./waterfall.sh
  ```
- Run with a custom descriptor:
  ```bash
  DESCRIPTOR="elsh(wpkh([beebc7e1/49'/1'/0']tpubDC2Q4xK4XH72GvSL1nBndkYAuqqJQP2fWHwKeDfg1GsTqszkZV9Cqk5PUKrg57ZhGcQhNLsi2mUtNKE5bcmDHKF41SnCpLvpGo3c83WT9ET/0/*))"
  ./waterfall.sh
  ```

  ## Response example
  ```
  ✅ Response for plain urlencoded descriptor received successfully. (HTTP 200)
  ✅ Server pub key received successfully. (HTTP 200)
  ✅ Descriptor encrypted successfully.
  ✅ Encrypted descriptor URL encoded successfully.
  ✅ Response for encrypted urlencoded descriptor received successfully. (HTTP 200)
  ✅ Response bodies are the same for both plain and encrypted descriptors.
  {
    "txs_seen": {
    ...
  ```