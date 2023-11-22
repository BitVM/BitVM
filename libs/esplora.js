/**********************************************************************
 * Copyright (c) 2019 Robin Linus                                     *
 * Distributed under the MIT software license, see                    *
 * http://www.opensource.org/licenses/mit-license.php.                *
 **********************************************************************/

/*
    Simple Esplora Client
    See Blockstream API Documentation
        https://github.com/Blockstream/esplora/blob/master/API.md
    Features: 
        - Mainnet & Testnet
        - Error Handling
        - Documentation
        - No Dependencies
        - Compatible with tree shaking
        - Error Handling API
        - most endpoints implemented
*/


// Base URI of the Esplora Server API endpoint (mainnet)
// const BASE_URI_MAINNET = `https://blockstream.info/api`;
const BASE_URI_MAINNET = `https://mutinynet.com/api`;

// Base URI of the Esplora Server API endpoint (testnet)
const BASE_URI_TESTNET = `https://blockstream.info/testnet/api`;

// Base URI
let BASE_URI = BASE_URI_MAINNET;

export function useTestnet() {
    BASE_URI = BASE_URI_TESTNET;
}

export function useMainnet() {
    BASE_URI = BASE_URI_MAINNET;
}


/**
 * Assert a HTTP response is OK. Otherwise throw an error with the server's error message.
 * 
 * @param {Response} response 
 * @return Promise<void>
 *
 * @example
 *
 *     assertOK(await fetch('/'))
 */
async function assertOK(response) {
    if (response.ok) return; // response is OK thus nothing to do.
    let message = await response.text();
    throw new EsploraError(message);
}

/**
 * Get information about an address 
 *
 * @param {string} address 
 * @return {object} {chain_stats, mempool_stats}
 *
 * @example
 *
 *     fetchAddressInfo('17A16QmavnUfCW11DAApiJxp7ARnxN5pGX')
 */
export async function fetchAddressInfo(address) {
    const response = await fetch(`${ BASE_URI }/address/${address}`);
    await assertOK(response);
    return response.json();
}


/**
 * Broadcast a raw transaction to the network.
 * The transaction should be provided as hex.
 * The txid will be returned on success.
 *
 * @param {string} rawTransaction 
 * @return {string} transaction id
 *
 * @example
 *
 *     broadcastTransaction('<<raw transaction in hex>>')
 */
export async function broadcastTransaction(rawTransaction) {
    const response = await fetch(
        `${BASE_URI}/tx`, {
            method: 'POST',
            body: rawTransaction
        }
    )
    await assertOK(response);
    return response.text();
}

/**
 * Get the list of unspent transaction outputs associated with the address.
 *
 * @param {string} address 
 * @return {object} { chain_stats, mempool_stats }
 *
 * @example
 *
 *     fetchUnspentOutputs('17A16QmavnUfCW11DAApiJxp7ARnxN5pGX')
 */
export async function fetchUnspentOutputs(address) {
    const response = await fetch(`${ BASE_URI }/address/${address}/utxo`);
    await assertOK(response);
    return response.json();
}

/**
 * Get transaction history for the specified address, sorted with newest first.
 *
 * @param {string} address 
 * @return {object} transactions
 *
 * @example
 *
 *     fetchTransactions('17A16QmavnUfCW11DAApiJxp7ARnxN5pGX')
 */
export async function fetchTransactions(address) {
    const response = await fetch(`${ BASE_URI }/address/${ address }/txs`);
    await assertOK(response);
    return response.json();
}


/**
 * Returns information about the transaction.
 *
 * @param {string} txid - The id of the tx to fetch.
 * @param {format} [format] - The return format. One of ('' | 'hex' | 'raw').
 * @return {object} The transaction
 *
 * @example
 *
 *     fetchTransaction('2b19a7287581da86de256536fb6ba1be1347bd6dd62a899e965b44374fdebfec', 'hex')
 */
export async function fetchTransaction(txid, format = '') {
    if(format) format = '/' + format;
    const response = await fetch(`${ BASE_URI }/tx/${ txid }${ format }`);
    await assertOK(response);
    if (format === 'hex')
        return response.text();
    if(format === 'raw')
        return response.arrayBuffer();
    return response.json();
}


/**
 * Returns information about the transaction's outspends.
 *
 * @param {string} txid - The id of the tx to fetch.
 * @return {object} The transaction outspends
 *
 * @example
 *
 *     fetchTransactionOutspends('2b19a7287581da86de256536fb6ba1be1347bd6dd62a899e965b44374fdebfec')
 */
export async function fetchTransactionOutspends(txid) {
    const response = await fetch(`${ BASE_URI }/tx/${ txid }/outspends`);
    await assertOK(response);
    return response.json();
}



/**
 * Returns the transaction confirmation status.
 *
 * @param {string} txid - The id of the tx to fetch the status for.
 * @return {object} the transaction confirmation status.
 *
 * @example
 *
 *     fetchTransactionStatus('2b19a7287581da86de256536fb6ba1be1347bd6dd62a899e965b44374fdebfec')
 */
export async function fetchTransactionStatus(txid) {
    const response = await fetch(`${ BASE_URI }/tx/${ txid }/status`);
    await assertOK(response);
    return response.json();
}



/**
 * Returns a merkle inclusion proof for the transaction.
 * Currently matches the merkle proof format used by Electrum's blockchain.transaction.get_merkle. 
 * Will eventually be changed to use bitcoind's merkleblock format instead.
 *
 * @param {string} txid 
 * @return {object} merkle proof
 *
 * @example
 *
 *     fetchInclusionProof('2b19a7287581da86de256536fb6ba1be1347bd6dd62a899e965b44374fdebfec')
 */
export async function fetchInclusionProof(txid) {
    const response = await fetch(`${ BASE_URI }/tx/${ txid }/merkle-proof`);
    await assertOK(response);
    return response.json();
}


/**
 * Get an object where the key is the confirmation target (in number of blocks) and the value is the estimated feerate (in sat/vB).
 * The available confirmation targets are 2, 3, 4, 6, 10, 20, 144, 504 and 1008 blocks.
 * For example: { "2": 87.882, "3": 87.882, "4": 87.882, "6": 68.285, "10": 1.027, "20": 1.027, "144": 1.027, "504": 1.027, "1008": 1.027 }
 *
 * 
 * @return {object} 
 *
 * @example
 *
 *     fetchFeeEstimate()
 */
export async function fetchFeeEstimate() {
    const response = await fetch(`${ BASE_URI }/fee-estimates`);
    await assertOK(response);
    return response.json();
}

/**
 * Get balance of an address in Satoshis
 *
 * @param {string} address 
 * @return { confirmed: Number, unconfirmed: Number } balance
 * 
 * @example
 *
 *     fetchBalance('17A16QmavnUfCW11DAApiJxp7ARnxN5pGX')
 */
export async function fetchBalance(address) {
    const addressInfo = await fetchAddressInfo(address);

    const confirmed = statsToBalance(addressInfo.chain_stats)
    const unconfirmed = statsToBalance(addressInfo.mempool_stats)
    const total = confirmed + unconfirmed;

    return { confirmed, unconfirmed, total };
}

function statsToBalance(stats) {
    const totalReceived = stats.funded_txo_sum;
    const totalSent = stats.spent_txo_sum;
    const balance = totalReceived - totalSent;
    return balance;
}

/**
 * Returns information about a block.
 * Available fields: 
 * id, height, version, timestamp, bits, nonce, merkle_root, 
 * tx_count, size, weight and previousblockhash. 
 * See block format for more details.
 * 
 * The response from this endpoint can be cached indefinitely.
 * 
 * @param {string} hash
 * @return {object} block
 * 
 * @example
 *
 *     fetchBlock('00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04')
 */
export async function fetchBlock(hash) {
    const response = await fetch(`${ BASE_URI }/block/${ hash }`);
    await assertOK(response);
    return response.json();
}


/**
 * Returns the hex-encoded block header.
 * 
 * 
 * @param {string} hash - The block hash 
 * @return {string} hex-encoded block header
 * 
 * @example
 *
 *     fetchBlock('00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04')
 */
export async function fetchBlockHeader(hash) {
    const response = await fetch(`${ BASE_URI }/block/${ hash }/header`);
    await assertOK(response);
    return response.text();
}


/**
 * Returns the hash of the block currently at height.
 *
 * @param {Number} height
 * @return {string} block hash
 * 
 * @example
 *
 *     fetchBlockAtHeight(600000)
 */
export async function fetchBlockAtHeight(height) {
    const response = await fetch(`${ BASE_URI }/block-height/${ height }`);
    await assertOK(response);
    return response.text();
}

/**
 * Returns the transaction at index within the specified block.
 *
 * @param {String} blockHash
 * @param {Number} index
 * @return {string} transaction hash
 * 
 * @example
 *
 *     fetchTransationInBlock('00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04',42);
 */
export async function fetchTransationInBlock(blockHash, index) {
    const response = await fetch(`${ BASE_URI }/block/${ blockHash }/txid/${ index }`);
    await assertOK(response);
    return response.text();
}


/**
 * Returns a list of all txids in the block.
 *
 * @param {String} blockHash
 * @return {string} transaction hash
 * 
 * @example
 *
 *     fetchTXIDsInBlock('00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04');
 */
export async function fetchTXIDsInBlock(blockHash) {
    const response = await fetch(`${ BASE_URI }/block/${ blockHash }/txids`);
    await assertOK(response);
    return response.json();
}

/**
 * Returns the height of the last block.
 *
 * @return {Number} block height
 * 
 * @example
 *
 *     fetchLatestBlockHeight()
 */
export async function fetchLatestBlockHeight() {
    const response = await fetch(`${ BASE_URI }/blocks/tip/height`);
    await assertOK(response);
    return parseInt(await response.text());
}

/**
 * Get mempool backlog statistics. Returns an object with:
 * - count: the number of transactions in the mempool
 * - vsize: the total size of mempool transactions in virtual bytes
 * - total_fee: the total fee paid by mempool transactions in satoshis
 * - fee_histogram: mempool fee-rate distribution histogram
 * 
 * @return {object} mempool_stats
 * 
 * @example
 *
 *     fetchLatestBlockHash()
 */
export async function fetchMempool() {
    const response = await fetch(`${ BASE_URI }/mempool`);
    await assertOK(response);
    return response.json();
}


/**
 * Returns the hash of the last block.
 *
 * @return {string} block hash
 * 
 * @example
 *
 *     fetchLatestBlockHash()
 */
export async function fetchLatestBlockHash() {
    const response = await fetch(`${ BASE_URI }/blocks/tip/hash`);
    await assertOK(response);
    return response.text();
}


/**
 * Set of error codes of the esplora API
 *
 */
export const ErrorCode = {
    UNKNOWN: 1000000,
    MISSING_INPUTS: -25
}

/**
 * Parse Esplora API errors
 *
 */
class EsploraError extends Error {

    constructor(message) {
        // Parse RPC error name
        let name = message.match(/^.* RPC error/);
        if (name) name = name[0];

        // Clean up RPC error response to parse the JSON
        message = message.replace(/^.* RPC error: /, '');

        let code = ErrorCode.UNKNOWN;

        // try to parse the response as JSON
        try {
            message = JSON.parse(message);
            code = message.code;
            message = message.message;
        } catch (e) {
            // can not parse JSON. Thus, we treat the response as plain text. 
        }

        // Initialization
        super(message);
        this.name = name || 'Esplora Error';
        this.code = code;
    }
}