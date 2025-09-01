# Waterfalls API Documentation

This document describes all available API endpoints for the Waterfalls server, which provides blockchain data indexing and querying capabilities for Bitcoin and Elements/Liquid networks.

## Waterfalls Endpoints

These endpoints provide transaction history and UTXO data for descriptors or addresses. Available in both JSON and CBOR formats.

### Waterfalls Data (JSON)
```
GET /v2/waterfalls?<query_params>
```

### Waterfalls Data (CBOR)
```
GET /v2/waterfalls.cbor?<query_params>
```

**Note:** v1 exists for compatibility and v3 endpoints have been removed and return 404.

**Query Parameters:**

- `descriptor` (string): Bitcoin/Elements descriptor (plain text or encrypted with server key)
  - Cannot be used together with `addresses`
  - Supports encryption using age encryption with server's public key
  - Network validation: mainnet descriptors (xpub) cannot be used on testnet/regtest
  
- `addresses` (string): Comma-separated list of Bitcoin/Elements addresses
  - Cannot be used together with `descriptor`
  - Maximum addresses limited by server configuration
  - Addresses cannot be blinded (confidential)
  
- `page` (integer, optional): Page number for pagination (default: 0)

- `to_index` (integer, optional): Maximum derivation index for descriptors (default: 0)

- `utxo_only` (boolean, optional): Return only unspent outputs (default: false)

**Response Format (JSON):**
```json
{
  "txs_seen": {
    "descriptor_or_addresses": [
      {
        "txid": "transaction_id",
        "height": 12345,
        "block_hash": "block_hash",
        "block_timestamp": 1234567890,
        "v": 1
      }
    ]
  },
  "page": 0,
  "tip": "current_tip_hash"
}
```

**Differences between v1 and v2:**
- v2 includes `tip` field in response

## Base Endpoints

### Server Information

#### Get Server Public Key
```
GET /v1/server_recipient
```
Returns the server's public key for encryption purposes.

**Response:** Plain text string containing the public key

#### Get Server Address  
```
GET /v1/server_address
```
Returns the server's Bitcoin/Elements address for message signing verification.

**Response:** Plain text string containing the address

#### Time Since Last Block
```
GET /v1/time_since_last_block
```
Returns the time elapsed since the last block and a freshness indicator.

**Response:** Plain text describing time elapsed and status (e.g., "120 seconds since last block, less than 10 minutes")

#### Build Information
```
GET /v1/build_info
```
Returns build and version information including git commit ID.

**Response (JSON):**
```json
{
  "version": "0.9.4",
  "git_commit": "a1b2c3d4e5f6789..."
}
```



## Blockchain Data Endpoints

### Get Tip Hash
```
GET /blocks/tip/hash
```
Returns the hash of the current blockchain tip.

**Response:** Plain text string containing the block hash

### Get Block Hash by Height
```
GET /block-height/{height}
```
Returns the block hash for a specific block height.

**Parameters:**
- `height` (integer): Block height

**Response:** Plain text string containing the block hash, or 404 if not found

### Get Block Header
```
GET /block/{hash}/header
```
Returns the block header for a specific block hash.

**Parameters:**
- `hash` (string): Block hash

**Response:** Hex-encoded block header, or 404 if not found

### Get Raw Transaction
```
GET /tx/{txid}/raw
```
Returns the raw transaction data.

**Parameters:**
- `txid` (string): Transaction ID

**Response:** Binary transaction data (application/octet-stream)

### Get Address Transactions
```
GET /address/{address}/txs
```
Returns transaction history for a specific address in Esplora-compatible format.

**Parameters:**
- `address` (string): Bitcoin/Elements address

**Response (JSON):**
```json
[
  {
    "txid": "transaction_id",
    "status": {
      "block_height": 12345,
      "block_hash": "block_hash_or_null"
    }
  }
]
```

## Transaction Operations

### Broadcast Transaction
```
POST /tx
```
Broadcasts a raw transaction to the network.

**Request Body:** Raw transaction hex string

**Response:** 
- Success (200): Transaction ID
- Error (400): Error message

## Monitoring

### Prometheus Metrics
```
GET /metrics
```
Returns Prometheus-formatted metrics for monitoring.

**Response:** Text format metrics (text/plain)

## Error Responses

The API returns appropriate HTTP status codes:

- `200 OK`: Successful request
- `400 Bad Request`: Invalid parameters or transaction broadcast failure
- `404 Not Found`: Resource not found (block, transaction, endpoint)
- `500 Internal Server Error`: Server error

Common error conditions:
- `AtLeastOneFieldMandatory`: Neither descriptor nor addresses provided
- `CannotSpecifyBothDescriptorAndAddresses`: Both descriptor and addresses provided
- `WrongNetwork`: Network mismatch (e.g., mainnet descriptor on testnet)
- `TooManyAddresses`: Exceeds maximum address limit
- `AddressCannotBeBlinded`: Blinded/confidential address provided
- `InvalidTxid`: Malformed transaction ID
- `InvalidBlockHash`: Malformed block hash
- `CannotFindTx`: Transaction not found
- `CannotFindBlockHeader`: Block header not found

## Client Usage Examples

The codebase includes a `WaterfallClient` class with the following methods:

### Waterfalls Queries
```rust
// Query with descriptor (v2, JSON)
let (response, headers) = client.waterfalls(descriptor).await?;

// Query with addresses
let (response, headers) = client.waterfalls_addresses(&addresses).await?;

// Version-specific queries
let (response, headers) = client.waterfalls_v1(descriptor).await?;
let (response, headers) = client.waterfalls_v2(descriptor).await?;

// UTXO-only query
let (response, headers) = client.waterfalls_v2_utxo_only(descriptor).await?;

// Generic version with all parameters
let (response, headers) = client.waterfalls_version(
    descriptor, 
    version, 
    page, 
    to_index, 
    utxo_only
).await?;
```

### Blockchain Data
```rust
// Get current tip
let tip_hash = client.tip_hash().await?;

// Get block header
let header = client.header(block_hash).await?;

// Get transaction
let transaction = client.tx(txid).await?;

// Get address transactions
let txs_json = client.address_txs(&address).await?;
```

### Server Information
```rust
// Get server public key
let recipient = client.server_recipient().await?;

// Get server address
let address = client.server_address().await?;
```

### Transaction Broadcasting
```rust
// Broadcast transaction
let txid = client.broadcast(&transaction).await?;
```

## Security Features

- **Message Signing**: Responses include cryptographic signatures in headers:
  - `X-Content-Signature`: Message signature
  - `X-Content-Digest`: Content digest
  - `X-Server-Address`: Server address for verification

- **Encryption Support**: Descriptors can be encrypted using age encryption with the server's public key

- **CORS Support**: Configurable CORS headers for web client access

## Rate Limiting and Caching

- Responses include appropriate cache control headers
- Address and transaction endpoints have long cache times for confirmed data
- Mempool/tip data has shorter cache times or no caching
