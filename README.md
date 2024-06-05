

# Waterfall

Waterfall is a proposed new scanning mechanism for web light-clients wallets that leverages a new server endpoint.

## Current client

Currently used in https://liquidwebwallet.org/

Due to browser limitations the web wallet must use HTTP esplora API. 

With this API we cannot batch requests like it's done in the electrum client, and we cannot make requests concurrently because rate limitation is enforced in the server, this result in very poor scan performance.

Since we are persisting wallet data in the browser (encrypted), the scan following the first are faster.

### Scan

Txs | First          | Following
----|----------------|----------------
 80 | 66s (344 reqs) | 33s (187 reqs)
  3 | 11s (63 reqs)  | 11s (65 reqs)

## New client

Currently available at https://liquidwebwallet.org/waterfall

The new waterfall client avoids multiple requests by sending the bitcoin descriptor to the server.
This has privacy implications, but we argue it's not that different than sending all of our addresses separately to the server. Specifically in the latter case we are not sending the knowledge of future addresses that are derivable from the descriptor in the former case. The real privacy gain is moving to a self-hosted server or to a personal node.
Moreover, liquid specifically has the advantage of having confidential transactions and the blinding key is not sent to the server, thus a malicious server would know about the transactions of the wallet, but nothing about the assets exchanged and the value transacted.

### Scan

Note the scan results in the first iteration includes the transaction unblinding which is roughly 100ms per tx.

Txs | First         | Following
----|---------------|-------------
 80 | 22s (85 reqs) | 1s (5 reqs)
  3 | 2s (11 reqs)  | 1s (5 reqs)


## ADR

* The endpoint is GET, allowing requests to be cached for a minimum amount of time (even 5s) to prevent DOS. GET endpoint requires extra care for privacy and must be performed only via HTTPS and the server must not save server logs.
* Instead of developing the new endpoint in electrs, a separate executable has been created for this reasons:
    * speed of development (we may decide to do it in electrs in the future)
    * specific data model for the needed endpoint that doesn't fit in the current electrs data model. In particular:
        * in electrs is required to iterate values in the db, preventing the use of the "multi get" calls to speed up multiple row fetching, which is extremely needed to recover hundreds of script pubkeys
        * in electrs much more information is stored, by instead saving only the strictly needed more data can fit in memory
* The waterfall endpoint mirrors all the esplora endpoints (possibly via a web server like nginx) with the exception of the waterfall endpoint
* The format of the data returned resembles what you have in Esplora with multiple `script_get_history` calls, to minimize client changes needed. The only exception is giving some extra information (block timestamp) to avoid even more requests.
* Data returned in the endpoint mixes data in blocks and in mempool, since nature of the data differs (eg you could cache data coming from blocks for a minute) there could be some advantages in separating data returned in different endpoints, but we decided the gains are not worth the complexity
