Before running the demo for the first time, see [Environment Setup](#environment-setup) section below.

# Demo Prep: Funding UTXOs
The bridge peg-in and peg-out execution consumes three funding UTXOs. For convenience, prepare them before running the demo. This process remains the same across all scenarios. You can use the recommended amounts as below:

1. Peg-in graph - 'peg-in depost' tx input: **2097447 SAT** - will be spent by [DEPOSITOR] (use `-d` to get their address)
2. Peg-out graph - 'peg-out confirm' tx input: **3562670 SAT** - will be spent by [OPERATOR] (use `-o` to get their address)
3. Withdrawer peg-out - 'peg-out' tx input: **2097274 SAT** - will be spent by [OPERATOR] (use `-o` to get their address)

# Demo Steps
The following is the list of command line arguments that are passed to the CLI tool in sequence by the respective actors. The arguments can be used either with `cargo run --bin bridge --` or when running the CLI binary directly.

## Rejected Disprove Scenario (a.k.a. 'happy peg-out' execution path).
#### [DEPOSITOR] Initiate peg-in
`<TXID>:<VOUT>` = Bridge deposit UTXO that includes the expected peg-in amount. It must be spendable by the depositor private key. Suggested test amount: `2097447 sats`. It is the UTXO #1 in [Demo Prep](#demo-prep-funding-utxos).
```
-n -u <TXID>:<VOUT> -d <EVM_ADDRESS>
```
#### [OPERATOR] Create peg-out graph
`<TXID>:<VOUT>` = UTXO funding the peg-out confirm tx. Must be spendable by the operator private key. Suggested test amount: `3562670 sats`. It is the UTXO #2 in [Demo Prep](#demo-prep-funding-utxos).
```
-t -u <TXID>:<VOUT> -i <PEG_IN_GRAPH_ID>
```
#### [VERIFIER_0] Push verifier_0 nonces for peg-in graph
```
-c -i <GRAPH_ID>
```
#### [VERIFIER_1] Push verifier_1 nonces for peg-in graph
```
-c -i <GRAPH_ID>
```
#### [VERIFIER_0] Push verifier_0 signatures for peg-in graph
```
-g -i <GRAPH_ID>
```
#### [VERIFIER_1] Push verifier_1 signatures for peg-in graph
```
-g -i <GRAPH_ID>
```
#### [OPERATOR] or [VERIFIER_0] or [VERIFIER_1] Broadcast peg-in confirm
```
-b pegin -g <PEG_IN_GRAPH_ID> confirm
```
Record the peg-in confirm txid.
#### [VERIFIER_0] Push verifier_0 nonces for peg-out graph
```
-c -i <GRAPH_ID>
```
#### [VERIFIER_1] Push verifier_1 nonces for peg-out graph
```
-c -i <GRAPH_ID>
```
#### [VERIFIER_0] Push verifier_0 signatures for peg-out graph
```
-g -i <GRAPH_ID>
```
#### [VERIFIER_1] Push verifier_1 signatures for peg-out graph
```
-g -i <GRAPH_ID>
```
#### [OPERATOR] Mock L2 peg-out event (requires peg-in confirm txid mined earlier)
> [!IMPORTANT]
> Start the CLI in interactive mode here.

`<TXID>:<VOUT>` = The peg-in confirm txid recorded above and output index 0.
```
-x -u <TXID>:<VOUT>
```
#### [OPERATOR] Broadcast peg-out
`<TXID>:<VOUT>` = UTXO funding the payout to the withdrawer. Must be spendable by the operator private key. Suggested test amount: `2097274 sats`. It is the UTXO #3 in [Demo Prep](#demo-prep-funding-utxos).
```
-b tx -g <GRAPH_ID> -u <TXID>:<VOUT> peg_out
```
#### [OPERATOR] Broadcast peg-out confirm
```
-b tx -g <GRAPH_ID> peg_out_confirm
```
#### [OPERATOR] Broadcast kick-off 1
```
-b tx -g <GRAPH_ID> kick_off_1
```
#### [OPERATOR] Broadcast kick-off 2
```
-b tx -g <GRAPH_ID> kick_off_2
```
#### [OPERATOR] Broadcast assert-initial
```
-b tx -g <GRAPH_ID> assert_initial
```
#### [OPERATOR] Broadcast assert-commit 1
```
-b tx -g <GRAPH_ID> assert_commit_1
```
#### [OPERATOR] Broadcast assert-commit 2
```
-b tx -g <GRAPH_ID> assert_commit_2
```
#### [OPERATOR] Broadcast assert-final
```
-b tx -g <GRAPH_ID> assert_final
```
#### [VERIFIER_1] Broadcast disprove (should fail)
`<BTC_ADDRESS>` = Receiver of the disprove reward.
```
-b tx -g <GRAPH_ID> -a <BTC_ADDRESS> disprove
```
#### [OPERATOR] Broadcast take 2
```
-b tx -g <GRAPH_ID> take_2
```

## Successful Disprove Scenario (a.k.a. 'unhappy peg-out' execution path).
#### [DEPOSITOR] Initiate peg-in
`<TXID>:<VOUT>` = Bridge deposit UTXO that includes the expected peg-in amount. It must be spendable by the depositor private key. Suggested test amount: `2097447 sats`.
```
-n -u <TXID>:<VOUT> -d <EVM_ADDRESS>
```
#### [OPERATOR] Create peg-out graph
`<TXID>:<VOUT>` = UTXO funding the peg-out confirm tx. Must be spendable by the operator private key. Suggested test amount: `3562670 sats`.
```
-t -u <TXID>:<VOUT> -i <PEG_IN_GRAPH_ID>
```
#### [VERIFIER_0] Push verifier_0 nonces for peg-in graph
```
-c -i <GRAPH_ID>
```
#### [VERIFIER_1] Push verifier_1 nonces for peg-in graph
```
-c -i <GRAPH_ID>
```
#### [VERIFIER_0] Push verifier_0 signatures for peg-in graph
```
-g -i <GRAPH_ID>
```
#### [VERIFIER_0] Push verifier_1 signatures for peg-in graph
```
-g -i <GRAPH_ID>
```
#### [OPERATOR] or [VERIFIER_0] or [VERIFIER_1] Broadcast peg-in confirm
```
-b pegin -g <PEG_IN_GRAPH_ID> confirm
```
Record the peg-in confirm txid.
#### [VERIFIER_0] Push verifier_0 nonces for peg-out graph
```
-c -i <GRAPH_ID>
```
#### [VERIFIER_1] Push verifier_1 nonces for peg-out graph
```
-c -i <GRAPH_ID>
```
#### [VERIFIER_0] Push verifier_0 signatures for peg-out graph
```
-g -i <GRAPH_ID>
```
#### [VERIFIER_1] Push verifier_1 signatures for peg-out graph
```
-g -i <GRAPH_ID>
```
#### [OPERATOR] Mock L2 peg-out event (requires peg-in confirm txid mined earlier)
> [!IMPORTANT]
> Start the CLI in interactive mode here.

`<TXID>:<VOUT>` = The peg-in confirm txid recorded above and output index 0.
```
-x -u <TXID>:<VOUT>
```
#### [OPERATOR] Broadcast peg-out
`<TXID>:<VOUT>` = UTXO funding the payout to the withdrawer. Must be spendable by the operator private key. Suggested test amount: `2097274 sats`.
```
-b tx -g <GRAPH_ID> -u <TXID>:<VOUT> peg_out
```
#### [OPERATOR] Broadcast peg-out confirm
```
-b tx -g <GRAPH_ID> peg_out_confirm
```
#### [OPERATOR] Broadcast kick-off 1
```
-b tx -g <GRAPH_ID> kick_off_1
```
#### [OPERATOR] Broadcast kick-off 2
```
-b tx -g <GRAPH_ID> kick_off_2
```
#### [OPERATOR] Broadcast assert-initial
```
-b tx -g <GRAPH_ID> assert_initial
```
#### [OPERATOR] Broadcast assert-commit 1 with invalid proof
```
-b tx -g <GRAPH_ID> assert_commit_1_invalid
```
#### [OPERATOR] Broadcast assert-commit 2 with invalid proof
```
-b tx -g <GRAPH_ID> assert_commit_2_invalid
```
#### [OPERATOR] Broadcast assert-final
```
-b tx -g <GRAPH_ID> assert_final
```
#### [VERIFIER_1] Broadcast disprove
`<BTC_ADDRESS>` = Receiver of the disprove reward.
```
-b tx -g <GRAPH_ID> -a <BTC_ADDRESS> disprove
```

# Environment Setup
Clone and build this repository. The CLI executable is called `bridge`.

## [DEPOSITOR] and [OPERATOR] and [VERIFIER_0]
All the above users can execute commands using a single setup (from the same directory).

#### `bridge.toml`
Sample `bridge.toml` file that contains private keys of protocol participants and the ZK proof verifying key:
```toml
[keys]
depositor = "b8f17ea979be24199e7c3fec71ee88914d92fd4ca508443f765d56ce024ef1d7"
operator = "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac"
verifier = "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2"
verifying_key = "9c3815c2ec66950b63e60c86dc9a2a658e0224d55ea45efe1f633be052dc7d867aff76a9e983210318f1b808aacbbba1dc04b6ac4e6845fa0cc887aeacaf5a068ab9aeaf8142740612ff2f3377ce7bfa7433936aaa23e3f3749691afaa06301fd03f043c097556e7efdf6862007edf3eb868c736d917896c014c54754f65182ae0c198157f92e667b6572ba60e6a52d58cb70dbeb3791206e928ea5e65c6199d25780cedb51796a8a43e40e192d1b23d0cfaf2ddd03e4ade7c327dbc427999244bf4b47b560cf65d672c86ef448eb5061870d3f617bd3658ad6917d0d32d9296020000000000000008f167c3f26c93dbfb91f3077b66bc0092473a15ef21c30f43d3aa96776f352a33622830e9cfcb48bdf8d3145aa0cf364bd19bbabfb3c73e44f56794ee65dc8a"
```
Place the file in `.bitvm-bridge` directory in the user home directory.

#### `.env`
Sample `.env` file that must be present in the same directory as the CLI tool or any of its parent directories (if you clone this repository, you can put it in the root directory).
```
export BRIDGE_DATA_STORE_CLIENT_DATA_SUFFIX=-"bridge-client-data-demo-feb-2025.json"

export BRIDGE_AWS_ACCESS_KEY_ID=""
export BRIDGE_AWS_SECRET_ACCESS_KEY=""
export BRIDGE_AWS_REGION=""
export BRIDGE_AWS_BUCKET=""

# All verifier public keys
export VERIFIERS="026cc14f56ad7e8fdb323378287895c6c0bcdbb37714c74fba175a0c5f0cd0d56f,02452556ed6dbac394cbb7441fbaf06c446d1321467fa5a138895c6c9e246793dd"
```

## [VERIFIER_1]
Install the CLI tool in a different directory and make sure it doesn't share the `.env` file with the setup above. You can either clone this repository at another location or just copy the binary along with the .env.

#### `bridge.toml`
Create a 'bitvm-bridge-verifier-1' directory there and put the following `bridge.toml` file there:
```toml
[keys]
verifier = "fc294c70faf210d4d0807ea7a3dba8f7e41700d90c119e1ae82a0687d89d297f"
verifying_key = "9c3815c2ec66950b63e60c86dc9a2a658e0224d55ea45efe1f633be052dc7d867aff76a9e983210318f1b808aacbbba1dc04b6ac4e6845fa0cc887aeacaf5a068ab9aeaf8142740612ff2f3377ce7bfa7433936aaa23e3f3749691afaa06301fd03f043c097556e7efdf6862007edf3eb868c736d917896c014c54754f65182ae0c198157f92e667b6572ba60e6a52d58cb70dbeb3791206e928ea5e65c6199d25780cedb51796a8a43e40e192d1b23d0cfaf2ddd03e4ade7c327dbc427999244bf4b47b560cf65d672c86ef448eb5061870d3f617bd3658ad6917d0d32d9296020000000000000008f167c3f26c93dbfb91f3077b66bc0092473a15ef21c30f43d3aa96776f352a33622830e9cfcb48bdf8d3145aa0cf364bd19bbabfb3c73e44f56794ee65dc8a"
```
#### `.env`
```
export BRIDGE_DATA_STORE_CLIENT_DATA_SUFFIX=-"bridge-client-data-demo-feb-2025.json"

export BRIDGE_AWS_ACCESS_KEY_ID=""
export BRIDGE_AWS_SECRET_ACCESS_KEY=""
export BRIDGE_AWS_REGION=""
export BRIDGE_AWS_BUCKET=""

export KEY_DIR="bitvm-bridge-verifier-1"

# All verifier public keys
export VERIFIERS="026cc14f56ad7e8fdb323378287895c6c0bcdbb37714c74fba175a0c5f0cd0d56f,02452556ed6dbac394cbb7441fbaf06c446d1321467fa5a138895c6c9e246793dd"
```
