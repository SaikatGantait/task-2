import express from "express";
import { Transaction, PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";
import bs58 from "bs58";
import crypto from "crypto";

// ─── Constants ───────────────────────────────────────────────────────────────
const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";
const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

// ─── Account Model ───────────────────────────────────────────────────────────
interface AccountData {
  lamports: number;
  owner: string;
  data: Buffer;
  executable: boolean;
}

// ─── In-Memory Ledger State ──────────────────────────────────────────────────
const ledger = new Map<string, AccountData>();
let currentSlot = 1;
let currentBlockHeight = 1;
const issuedBlockhashes = new Set<string>();
const processedSigs = new Map<string, { slot: number }>();

function getAccount(pubkey: string): AccountData | null {
  return ledger.get(pubkey) ?? null;
}

function getOrCreateAccount(pubkey: string): AccountData {
  let acc = ledger.get(pubkey);
  if (!acc) {
    acc = {
      lamports: 0,
      owner: SYSTEM_PROGRAM_ID,
      data: Buffer.alloc(0),
      executable: false,
    };
    ledger.set(pubkey, acc);
  }
  return acc;
}

function generateBlockhash(): string {
  const hash = bs58.encode(crypto.randomBytes(32));
  issuedBlockhashes.add(hash);
  return hash;
}

function rentExemptMin(size: number): number {
  return (size + 128) * 2;
}

function incrementSlot(): void {
  currentSlot++;
  currentBlockHeight++;
}

function randomSignature(): string {
  return bs58.encode(crypto.randomBytes(64));
}

// ─── System Program ──────────────────────────────────────────────────────────
function execSystemProgram(
  accounts: { pubkey: string; isSigner: boolean; isWritable: boolean }[],
  data: Buffer,
  signers: Set<string>
): void {
  const disc = data.readUInt32LE(0);

  switch (disc) {
    case 0: {
      // CreateAccount
      const lamports = Number(data.readBigUInt64LE(4));
      const space = Number(data.readBigUInt64LE(12));
      const owner = new PublicKey(data.subarray(20, 52)).toBase58();
      const payerKey = accounts[0].pubkey;
      const newKey = accounts[1].pubkey;

      if (!signers.has(payerKey)) throw new Error("Payer must be a signer");
      if (!signers.has(newKey))
        throw new Error("New account must be a signer");

      const existing = getAccount(newKey);
      if (existing && (existing.lamports > 0 || existing.data.length > 0)) {
        throw new Error("Account already exists");
      }

      const payer = getOrCreateAccount(payerKey);
      if (payer.lamports < lamports) throw new Error("Insufficient funds");
      payer.lamports -= lamports;

      ledger.set(newKey, {
        lamports,
        owner,
        data: Buffer.alloc(space),
        executable: false,
      });
      break;
    }

    case 2: {
      // Transfer
      const lamports = Number(data.readBigUInt64LE(4));
      const fromKey = accounts[0].pubkey;
      const toKey = accounts[1].pubkey;

      if (!signers.has(fromKey)) throw new Error("Source must be a signer");

      const from = getOrCreateAccount(fromKey);
      if (from.lamports < lamports) throw new Error("Insufficient funds");

      const to = getOrCreateAccount(toKey);
      from.lamports -= lamports;
      to.lamports += lamports;
      break;
    }

    default:
      // Silently ignore Assign, Allocate, etc.
      break;
  }
}

// ─── SPL Token Program ───────────────────────────────────────────────────────
function execTokenProgram(
  accounts: { pubkey: string; isSigner: boolean; isWritable: boolean }[],
  data: Buffer,
  signers: Set<string>
): void {
  const disc = data.readUInt8(0);

  switch (disc) {
    case 0: // InitializeMint (legacy, same data layout as InitializeMint2)
    case 20: {
      // InitializeMint2
      const decimals = data.readUInt8(1);
      const mintAuthority = new PublicKey(data.subarray(2, 34)).toBase58();
      const hasFreezeAuth = data.readUInt8(34);
      const freezeAuthority = hasFreezeAuth
        ? new PublicKey(data.subarray(35, 67)).toBase58()
        : null;

      const mintKey = accounts[0].pubkey;
      const mint = getOrCreateAccount(mintKey);

      if (mint.data.length >= 82 && mint.data[45] === 1) {
        throw new Error("Mint already initialized");
      }

      // Mint layout: 82 bytes
      const buf = Buffer.alloc(82);
      buf.writeUInt32LE(1, 0); // mintAuthorityOption = Some
      new PublicKey(mintAuthority).toBuffer().copy(buf, 4);
      // supply = 0 at offset 36 (already zeroed)
      buf.writeUInt8(decimals, 44);
      buf.writeUInt8(1, 45); // isInitialized
      if (freezeAuthority) {
        buf.writeUInt32LE(1, 46); // freezeAuthorityOption = Some
        new PublicKey(freezeAuthority).toBuffer().copy(buf, 50);
      }

      mint.data = buf;
      mint.owner = TOKEN_PROGRAM_ID;
      break;
    }

    case 1: {
      // InitializeAccount (legacy) — owner from accounts[2]
      const tokenKey = accounts[0].pubkey;
      const mintKey = accounts[1].pubkey;
      const ownerKey = accounts[2].pubkey;

      const tokenAcc = getOrCreateAccount(tokenKey);
      const buf = Buffer.alloc(165);
      new PublicKey(mintKey).toBuffer().copy(buf, 0);
      new PublicKey(ownerKey).toBuffer().copy(buf, 32);
      buf.writeUInt8(1, 108); // state = Initialized

      tokenAcc.data = buf;
      tokenAcc.owner = TOKEN_PROGRAM_ID;
      break;
    }

    case 18: {
      // InitializeAccount3 — owner from instruction data
      const ownerKey = new PublicKey(data.subarray(1, 33)).toBase58();
      const tokenKey = accounts[0].pubkey;
      const mintKey = accounts[1].pubkey;

      const tokenAcc = getOrCreateAccount(tokenKey);
      const buf = Buffer.alloc(165);
      new PublicKey(mintKey).toBuffer().copy(buf, 0);
      new PublicKey(ownerKey).toBuffer().copy(buf, 32);
      buf.writeUInt8(1, 108);

      tokenAcc.data = buf;
      tokenAcc.owner = TOKEN_PROGRAM_ID;
      break;
    }

    case 7: {
      // MintTo
      const amount = Number(data.readBigUInt64LE(1));
      const mintKey = accounts[0].pubkey;
      const destKey = accounts[1].pubkey;
      const authKey = accounts[2].pubkey;

      if (!signers.has(authKey)) throw new Error("Authority must be a signer");

      const mint = getAccount(mintKey);
      if (!mint || mint.data.length < 82) throw new Error("Invalid mint");

      const mintAuth = new PublicKey(mint.data.subarray(4, 36)).toBase58();
      if (mintAuth !== authKey) throw new Error("Authority mismatch");

      const dest = getAccount(destKey);
      if (!dest || dest.data.length < 165)
        throw new Error("Invalid destination token account");

      const curAmt = Number(dest.data.readBigUInt64LE(64));
      dest.data.writeBigUInt64LE(BigInt(curAmt + amount), 64);

      const curSup = Number(mint.data.readBigUInt64LE(36));
      mint.data.writeBigUInt64LE(BigInt(curSup + amount), 36);
      break;
    }

    case 3: {
      // Transfer
      const amount = Number(data.readBigUInt64LE(1));
      const srcKey = accounts[0].pubkey;
      const dstKey = accounts[1].pubkey;
      const ownerKey = accounts[2].pubkey;

      if (!signers.has(ownerKey)) throw new Error("Owner must be a signer");

      const src = getAccount(srcKey);
      if (!src || src.data.length < 165)
        throw new Error("Invalid source token account");

      const srcOwner = new PublicKey(src.data.subarray(32, 64)).toBase58();
      if (srcOwner !== ownerKey) throw new Error("Owner mismatch");

      const srcAmt = Number(src.data.readBigUInt64LE(64));
      if (srcAmt < amount) throw new Error("Insufficient token balance");
      src.data.writeBigUInt64LE(BigInt(srcAmt - amount), 64);

      const dst = getAccount(dstKey);
      if (!dst || dst.data.length < 165)
        throw new Error("Invalid destination token account");
      const dstAmt = Number(dst.data.readBigUInt64LE(64));
      dst.data.writeBigUInt64LE(BigInt(dstAmt + amount), 64);
      break;
    }

    case 12: {
      // TransferChecked
      const amount = Number(data.readBigUInt64LE(1));
      const expectedDec = data.readUInt8(9);
      const srcKey = accounts[0].pubkey;
      const mintKey = accounts[1].pubkey;
      const dstKey = accounts[2].pubkey;
      const ownerKey = accounts[3].pubkey;

      if (!signers.has(ownerKey)) throw new Error("Owner must be a signer");

      const mint = getAccount(mintKey);
      if (!mint || mint.data.length < 82) throw new Error("Invalid mint");
      if (mint.data.readUInt8(44) !== expectedDec)
        throw new Error("Decimals mismatch");

      const src = getAccount(srcKey);
      if (!src || src.data.length < 165) throw new Error("Invalid source");
      const srcOwner = new PublicKey(src.data.subarray(32, 64)).toBase58();
      if (srcOwner !== ownerKey) throw new Error("Owner mismatch");

      const srcAmt = Number(src.data.readBigUInt64LE(64));
      if (srcAmt < amount) throw new Error("Insufficient token balance");
      src.data.writeBigUInt64LE(BigInt(srcAmt - amount), 64);

      const dst = getAccount(dstKey);
      if (!dst || dst.data.length < 165) throw new Error("Invalid destination");
      const dstAmt = Number(dst.data.readBigUInt64LE(64));
      dst.data.writeBigUInt64LE(BigInt(dstAmt + amount), 64);
      break;
    }

    case 8: {
      // Burn
      const amount = Number(data.readBigUInt64LE(1));
      const tokenKey = accounts[0].pubkey;
      const mintKey = accounts[1].pubkey;
      const ownerKey = accounts[2].pubkey;

      if (!signers.has(ownerKey)) throw new Error("Owner must be a signer");

      const tokenAcc = getAccount(tokenKey);
      if (!tokenAcc || tokenAcc.data.length < 165)
        throw new Error("Invalid token account");

      const tokenOwner = new PublicKey(
        tokenAcc.data.subarray(32, 64)
      ).toBase58();
      if (tokenOwner !== ownerKey) throw new Error("Owner mismatch");

      const bal = Number(tokenAcc.data.readBigUInt64LE(64));
      if (bal < amount) throw new Error("Insufficient token balance");
      tokenAcc.data.writeBigUInt64LE(BigInt(bal - amount), 64);

      const mint = getAccount(mintKey);
      if (!mint || mint.data.length < 82) throw new Error("Invalid mint");
      const supply = Number(mint.data.readBigUInt64LE(36));
      mint.data.writeBigUInt64LE(BigInt(supply - amount), 36);
      break;
    }

    case 9: {
      // CloseAccount
      const tokenKey = accounts[0].pubkey;
      const destKey = accounts[1].pubkey;
      const ownerKey = accounts[2].pubkey;

      if (!signers.has(ownerKey)) throw new Error("Owner must be a signer");

      const tokenAcc = getAccount(tokenKey);
      if (!tokenAcc || tokenAcc.data.length < 165)
        throw new Error("Invalid token account");

      const tokenOwner = new PublicKey(
        tokenAcc.data.subarray(32, 64)
      ).toBase58();
      if (tokenOwner !== ownerKey) throw new Error("Owner mismatch");

      const bal = Number(tokenAcc.data.readBigUInt64LE(64));
      if (bal !== 0) throw new Error("Token balance must be zero to close");

      const dest = getOrCreateAccount(destKey);
      dest.lamports += tokenAcc.lamports;
      ledger.delete(tokenKey);
      break;
    }

    default:
      throw new Error(`Unknown SPL Token instruction: ${disc}`);
  }
}

// ─── Associated Token Account Program ────────────────────────────────────────
function execAtaProgram(
  accounts: { pubkey: string; isSigner: boolean; isWritable: boolean }[],
  data: Buffer,
  signers: Set<string>
): void {
  const payerKey = accounts[0].pubkey;
  const ataKey = accounts[1].pubkey;
  const ownerKey = accounts[2].pubkey;
  const mintKey = accounts[3].pubkey;

  // Discriminator: 0 = Create, 1 = CreateIdempotent
  const disc = data.length > 0 ? data.readUInt8(0) : 0;
  const idempotent = disc === 1;

  if (!signers.has(payerKey)) throw new Error("Payer must be a signer");

  // Derive and verify ATA address
  const [derived] = PublicKey.findProgramAddressSync(
    [
      new PublicKey(ownerKey).toBuffer(),
      new PublicKey(TOKEN_PROGRAM_ID).toBuffer(),
      new PublicKey(mintKey).toBuffer(),
    ],
    new PublicKey(ATA_PROGRAM_ID)
  );
  if (derived.toBase58() !== ataKey) throw new Error("ATA address mismatch");

  // Check if already exists
  const existing = getAccount(ataKey);
  if (existing && (existing.lamports > 0 || existing.data.length > 0)) {
    if (idempotent) return; // CreateIdempotent succeeds silently
    throw new Error("ATA already exists");
  }

  // Fund from payer
  const rent = rentExemptMin(165);
  const payer = getOrCreateAccount(payerKey);
  if (payer.lamports < rent) throw new Error("Insufficient funds for rent");
  payer.lamports -= rent;

  // Create & initialize token account
  const buf = Buffer.alloc(165);
  new PublicKey(mintKey).toBuffer().copy(buf, 0);
  new PublicKey(ownerKey).toBuffer().copy(buf, 32);
  buf.writeUInt8(1, 108); // state = Initialized

  ledger.set(ataKey, {
    lamports: rent,
    owner: TOKEN_PROGRAM_ID,
    data: buf,
    executable: false,
  });
}

// ─── Instruction Dispatch ────────────────────────────────────────────────────
function executeInstruction(
  programId: string,
  accounts: { pubkey: string; isSigner: boolean; isWritable: boolean }[],
  data: Buffer,
  signers: Set<string>
): void {
  switch (programId) {
    case SYSTEM_PROGRAM_ID:
      execSystemProgram(accounts, data, signers);
      break;
    case TOKEN_PROGRAM_ID:
      execTokenProgram(accounts, data, signers);
      break;
    case ATA_PROGRAM_ID:
      execAtaProgram(accounts, data, signers);
      break;
    default:
      // Silently ignore unknown programs (e.g. compute budget, memo)
      break;
  }
}

// ─── Transaction Processing ──────────────────────────────────────────────────
function processTransaction(encodedTx: string, encoding: string): string {
  let txBuffer: Buffer;
  if (encoding === "base58") {
    txBuffer = Buffer.from(bs58.decode(encodedTx));
  } else {
    txBuffer = Buffer.from(encodedTx, "base64");
  }

  const transaction = Transaction.from(txBuffer);

  // Verify blockhash
  if (
    !transaction.recentBlockhash ||
    !issuedBlockhashes.has(transaction.recentBlockhash)
  ) {
    throw new Error("Invalid or unknown blockhash");
  }

  // Verify signatures
  const message = transaction.serializeMessage();
  const signers = new Set<string>();

  for (const { publicKey, signature } of transaction.signatures) {
    if (!signature || signature.every((b: number) => b === 0)) {
      throw new Error("Missing signature");
    }
    const valid = nacl.sign.detached.verify(
      new Uint8Array(message),
      new Uint8Array(signature),
      publicKey.toBytes()
    );
    if (!valid) throw new Error("Invalid signature");
    signers.add(publicKey.toBase58());
  }

  // Execute instructions sequentially
  for (const ix of transaction.instructions) {
    executeInstruction(
      ix.programId.toBase58(),
      ix.keys.map((k) => ({
        pubkey: k.pubkey.toBase58(),
        isSigner: k.isSigner,
        isWritable: k.isWritable,
      })),
      Buffer.from(ix.data),
      signers
    );
  }

  // Record signature and advance slot
  const txSig = bs58.encode(
    new Uint8Array(transaction.signatures[0].signature!)
  );
  processedSigs.set(txSig, { slot: currentSlot });
  incrementSlot();
  return txSig;
}

// ─── RPC Method Handlers ─────────────────────────────────────────────────────
type RpcHandler = (params: any[]) => any;

const rpcHandlers: Record<string, RpcHandler> = {
  // ── Cluster Info ──
  getVersion: () => ({ "solana-core": "1.18.0", "feature-set": 1 }),

  getSlot: () => currentSlot,

  getBlockHeight: () => currentBlockHeight,

  getHealth: () => "ok",

  // ── Blockhash ──
  getLatestBlockhash: () => ({
    context: { slot: currentSlot },
    value: {
      blockhash: generateBlockhash(),
      lastValidBlockHeight: currentBlockHeight + 150,
    },
  }),

  getRecentBlockhash: () => ({
    context: { slot: currentSlot },
    value: {
      blockhash: generateBlockhash(),
      feeCalculator: { lamportsPerSignature: 5000 },
    },
  }),

  isBlockhashValid: (params) => ({
    context: { slot: currentSlot },
    value: params[0] ? issuedBlockhashes.has(params[0]) : false,
  }),

  // ── Account Queries ──
  getBalance: (params) => {
    const pubkey = params[0];
    if (!pubkey) throw { code: -32602, message: "Missing pubkey" };
    const acc = getAccount(pubkey);
    return { context: { slot: currentSlot }, value: acc ? acc.lamports : 0 };
  },

  getAccountInfo: (params) => {
    const pubkey = params[0];
    if (!pubkey) throw { code: -32602, message: "Missing pubkey" };
    const acc = getAccount(pubkey);
    if (!acc) return { context: { slot: currentSlot }, value: null };
    return {
      context: { slot: currentSlot },
      value: {
        data: [acc.data.toString("base64"), "base64"],
        executable: acc.executable,
        lamports: acc.lamports,
        owner: acc.owner,
        rentEpoch: 0,
      },
    };
  },

  getMinimumBalanceForRentExemption: (params) => {
    const size = params[0];
    if (size === undefined || size === null)
      throw { code: -32602, message: "Missing dataSize" };
    return rentExemptMin(size);
  },

  // ── Token Queries ──
  getTokenAccountBalance: (params) => {
    const pubkey = params[0];
    if (!pubkey) throw { code: -32602, message: "Missing pubkey" };
    const acc = getAccount(pubkey);
    if (!acc || acc.owner !== TOKEN_PROGRAM_ID || acc.data.length < 165) {
      throw { code: -32602, message: "Not a token account" };
    }
    const mintKey = new PublicKey(acc.data.subarray(0, 32)).toBase58();
    const amount = Number(acc.data.readBigUInt64LE(64));
    const mintAcc = getAccount(mintKey);
    const decimals =
      mintAcc && mintAcc.data.length >= 82 ? mintAcc.data.readUInt8(44) : 0;
    return {
      context: { slot: currentSlot },
      value: {
        amount: amount.toString(),
        decimals,
        uiAmount: amount / Math.pow(10, decimals),
      },
    };
  },

  getTokenAccountsByOwner: (params) => {
    const ownerPubkey = params[0];
    const filter = params[1];
    if (!ownerPubkey || !filter)
      throw { code: -32602, message: "Invalid params" };

    const results: any[] = [];
    for (const [pubkey, acc] of ledger) {
      if (acc.owner !== TOKEN_PROGRAM_ID || acc.data.length < 165) continue;

      const tokenOwner = new PublicKey(acc.data.subarray(32, 64)).toBase58();
      if (tokenOwner !== ownerPubkey) continue;

      if (filter.mint) {
        const tokenMint = new PublicKey(acc.data.subarray(0, 32)).toBase58();
        if (tokenMint !== filter.mint) continue;
      }
      if (filter.programId && acc.owner !== filter.programId) continue;

      results.push({
        pubkey,
        account: {
          data: [acc.data.toString("base64"), "base64"],
          executable: acc.executable,
          lamports: acc.lamports,
          owner: acc.owner,
          rentEpoch: 0,
        },
      });
    }

    return { context: { slot: currentSlot }, value: results };
  },

  // ── Transaction Submission ──
  requestAirdrop: (params) => {
    const pubkey = params[0];
    const lamports = params[1];
    if (!pubkey || lamports === undefined)
      throw { code: -32602, message: "Invalid params" };

    const acc = getOrCreateAccount(pubkey);
    acc.lamports += lamports;

    const sig = randomSignature();
    processedSigs.set(sig, { slot: currentSlot });
    incrementSlot();
    return sig;
  },

  sendTransaction: (params) => {
    const encoded = params[0];
    if (!encoded) throw { code: -32602, message: "Missing transaction" };

    const options = params[1] || {};
    const encoding = options.encoding || "base64";

    try {
      return processTransaction(encoded, encoding);
    } catch (err: any) {
      throw { code: -32003, message: err.message || "Transaction failed" };
    }
  },

  getSignatureStatuses: (params) => {
    const sigs = params[0];
    if (!Array.isArray(sigs))
      throw { code: -32602, message: "Invalid params" };
    return {
      context: { slot: currentSlot },
      value: sigs.map((sig: string) => {
        const status = processedSigs.get(sig);
        if (!status) return null;
        return {
          slot: status.slot,
          confirmations: null,
          err: null,
          confirmationStatus: "confirmed",
        };
      }),
    };
  },

  // ── Compatibility Extras ──
  simulateTransaction: () => ({
    context: { slot: currentSlot },
    value: { err: null, logs: [], accounts: null, unitsConsumed: 0 },
  }),

  getFeeForMessage: () => ({
    context: { slot: currentSlot },
    value: 5000,
  }),

  getEpochInfo: () => ({
    absoluteSlot: currentSlot,
    blockHeight: currentBlockHeight,
    epoch: 0,
    slotIndex: currentSlot,
    slotsInEpoch: 432000,
    transactionCount: processedSigs.size,
  }),

  getGenesisHash: () => "GHtXjR3FHxFCsxEAxEt44hpKBorsEaKDJfJSsEy2E72",
};

// ─── Express Server ──────────────────────────────────────────────────────────
const app = express();
app.use(express.json());

app.post("/", (req, res) => {
  const { jsonrpc, id, method, params } = req.body;

  if (jsonrpc !== "2.0" || id === undefined || !method) {
    return res.json({
      jsonrpc: "2.0",
      id: id ?? null,
      error: { code: -32600, message: "Invalid request" },
    });
  }

  const handler = rpcHandlers[method];
  if (!handler) {
    return res.json({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: "Method not found" },
    });
  }

  try {
    const result = handler(params || []);
    return res.json({ jsonrpc: "2.0", id, result });
  } catch (err: any) {
    return res.json({
      jsonrpc: "2.0",
      id,
      error: {
        code: err.code || -32003,
        message: err.message || "Internal error",
      },
    });
  }
});

app.listen(3000, () => {
  console.log("Mini Solana Validator running on port 3000");
});
