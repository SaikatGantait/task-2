# Mini Solana Validator

An in-memory, single-node Solana-compatible JSON-RPC server. Accepts real Solana transactions (same binary wire format as mainnet) and executes them against an in-memory ledger. Supports the **System Program**, **SPL Token Program**, and **Associated Token Account Program** — standard Solana client libraries (`@solana/web3.js`, `@solana/spl-token`) can interact with this server as if it were a real Solana cluster.

## Quick Start

```bash
npm install && npm start
```

Server listens on **port 3000**.

## RPC Methods

### Cluster Info
| Method | Response |
|---|---|
| `getVersion` | `{ "solana-core": "1.18.0", "feature-set": 1 }` |
| `getSlot` | Current slot number |
| `getBlockHeight` | Current block height |
| `getHealth` | `"ok"` |

### Blockhash
| Method | Description |
|---|---|
| `getLatestBlockhash` | Returns a new blockhash. Server tracks issued blockhashes and rejects transactions using unknown ones. |

### Account Queries
| Method | Description |
|---|---|
| `getBalance` | Returns lamports for a pubkey (0 for unknown accounts) |
| `getAccountInfo` | Returns full account info or `null` |
| `getMinimumBalanceForRentExemption` | Returns rent-exempt minimum for a given data size |
| `getTokenAccountBalance` | Returns SPL token balance |
| `getTokenAccountsByOwner` | Returns token accounts filtered by mint or programId |

### Transactions
| Method | Description |
|---|---|
| `requestAirdrop` | Credits an account with SOL |
| `sendTransaction` | Decodes, verifies signatures (ed25519), and executes a real Solana transaction |
| `getSignatureStatuses` | Returns confirmation status for transaction signatures |

## Supported Programs

### System Program (`11111111111111111111111111111111`)
- **CreateAccount** — Create a new account with lamports, space, and owner
- **Transfer** — Transfer SOL between accounts

### SPL Token Program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`)
- **InitializeMint2** — Initialize a token mint
- **InitializeAccount3** — Initialize a token account
- **MintTo** — Mint tokens to an account
- **Transfer** — Transfer tokens between accounts
- **TransferChecked** — Transfer with decimals verification
- **Burn** — Burn tokens
- **CloseAccount** — Close a token account

### Associated Token Account Program (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`)
- **Create** — Derive PDA and create an associated token account
- **CreateIdempotent** — Same as Create but succeeds if ATA already exists

## Transaction Processing Pipeline

1. Deserialize base64-encoded transaction bytes
2. Verify blockhash was issued by this server
3. Verify all ed25519 signatures using `tweetnacl`
4. Execute each instruction sequentially against in-memory state
5. Record signature and increment slot

## Tech Stack

- **Runtime**: Node.js + TypeScript (via `tsx`)
- **HTTP**: Express
- **Crypto**: `tweetnacl` (ed25519), `bs58` (base58)
- **Solana**: `@solana/web3.js` (transaction deserialization, PublicKey operations)
- **Storage**: All state in memory (no database)

## Error Codes

| Code | Meaning |
|---|---|
| `-32601` | Method not found |
| `-32600` | Invalid request |
| `-32602` | Invalid params |
| `-32003` | Transaction failed |
