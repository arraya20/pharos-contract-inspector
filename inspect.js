#!/usr/bin/env node
// inspect.js — Pharos Contract Inspector CLI.
// ABI-free contract introspection: walks bytecode, resolves proxies, detects
// interfaces, inventories selectors, and flags privileged functions.
// Usage: node inspect.js <address> [--network testnet|mainnet] [--rpc URL] [--json]

import { readFileSync } from "fs";
import { Rpc } from "./lib/rpc.js";
import { disassemble } from "./lib/disasm.js";
import { KNOWN, PRIVILEGED, FINGERPRINTS, INTERFACE_IDS } from "./lib/signatures.js";
import { resolveProxy } from "./lib/proxy.js";
import { readMetadata, probeInterfaces } from "./lib/decode.js";
import { resolveMany } from "./lib/fourbyte.js";

// --- CLI args ---
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { network: "testnet", rpc: null, json: false, online: true };
  let addr = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--network" || args[i] === "-n") opts.network = args[++i];
    else if (args[i] === "--rpc") opts.rpc = args[++i];
    else if (args[i] === "--json") opts.json = true;
    else if (args[i] === "--offline") opts.online = false;
    else if (args[i] === "--help" || args[i] === "-h") { usage(); process.exit(0); }
    else if (!addr && args[i].startsWith("0x")) addr = args[i];
  }
  if (!addr) { usage(); process.exit(1); }
  opts.addr = addr;
  return opts;
}

function usage() {
  console.log(`
  Pharos Contract Inspector — ABI-free EVM contract introspection
  
  Usage: node inspect.js <0xADDRESS> [options]
  
  Options:
    -n, --network <testnet|mainnet>   Pharos network (default: testnet)
    --rpc <URL>                       Custom RPC endpoint
    --json                            Output raw JSON
    --offline                         Skip 4byte.directory lookups
    -h, --help                        Show this help
  
  Examples:
    node inspect.js 0xcfC8330f4BCAB529c625D12781b1C19466A9Fc8B --network testnet
    node inspect.js 0x000000000022D473030F116dDEE9F6B43aC78BA3 --n mainnet
    node inspect.js 0xcA11bde05977b3631167028862bE2a173976CA11 --json
  `.trim());
}

// --- main ---
async function main() {
  const opts = parseArgs();
  const networks = JSON.parse(readFileSync(new URL("./networks.json", import.meta.url), "utf8"));
  const net = networks[opts.network];
  if (!net) { console.error(`Unknown network: ${opts.network}`); process.exit(1); }
  const rpcUrl = opts.rpc || net.rpc;
  const rpc = new Rpc(rpcUrl);

  process.stderr.write(`Inspecting ${opts.addr} on ${net.name} (${net.chainId})...\n`);

  // 1. Code + EOA check
  const codeHex = await rpc.getCode(opts.addr);
  if (!codeHex || codeHex === "0x" || codeHex.length <= 2) {
    const bal = await rpc.getBalance(opts.addr);
    console.log(`\n  RESULT: EOA (Externally Owned Account)\n`);
    console.log(`  Address:       ${opts.addr}`);
    console.log(`  Balance:       ${Number(BigInt(bal)) / 1e18} ${net.nativeSymbol}`);
    return;
  }

  // 2. Disassemble bytecode → extract selectors + opcode signals
  const dis = disassemble(codeHex);

  // 3. Resolve proxy
  const proxy = await resolveProxy(rpc, opts.addr, codeHex);

  // 4. Known-function inventory
  const known = [];
  const unknown = [];
  const dangerous = [];

  for (const sel of dis.selectors) {
    const sig = KNOWN[sel] || null;
    if (sig) {
      known.push({ selector: sel, signature: sig });
    } else {
      unknown.push(sel);
    }
    if (PRIVILEGED[sel]) {
      dangerous.push({ selector: sel, signature: sig || PRIVILEGED[sel], reason: PRIVILEGED[sel] });
    }
  }

  // 5. Optional 4byte resolution for unknown selectors
  let resolved = {};
  if (unknown.length > 0 && opts.online) {
    process.stderr.write(`Resolving ${unknown.length} unknown selectors via 4byte.directory...\n`);
    resolved = await resolveMany(unknown);
  }

  // 6. Interface detection via supportsInterface
  const interfaces = [];
  if (known.some((k) => k.selector === "0x01ffc9a7")) {
    const probed = await probeInterfaces(rpc, opts.addr, INTERFACE_IDS);
    for (const p of probed) {
      if (p.supported) interfaces.push(p.name);
    }
  }

  // 7. Contract type fingerprinting
  const selSet = new Set(dis.selectors);
  const standards = [];
  for (const fp of FINGERPRINTS) {
    const matched = fp.required.every((s) => selSet.has(s));
    if (matched) standards.push(fp.name);
  }
  // Also check interfaceId-based detection
  for (const name of interfaces) {
    if (!standards.includes(name)) standards.push(name);
  }

  // 8. Metadata (best-effort eth_calls)
  const meta = await readMetadata(rpc, opts.addr);

  // 9. If it's a proxy, also inspect implementation
  let implDis = null;
  if (proxy.isProxy && proxy.impl) {
    const implCode = await rpc.getCode(proxy.impl);
    if (implCode && implCode !== "0x" && implCode.length > 2) {
      implDis = disassemble(implCode);
    }
  }

  // 10. Output
  if (opts.json) {
    console.log(JSON.stringify({
      address: opts.addr,
      network: opts.network,
      chainId: net.chainId,
      bytecode: { size: dis.codeSize, head: codeHex.slice(0, 10) },
      proxy: proxy.isProxy ? { type: proxy.type, implementation: proxy.impl, admin: proxy.admin } : null,
      metadata: meta,
      standards,
      interfaces,
      selectors: { total: dis.selectors.length, known: known.length, unknown: unknown.length },
      functions: {
        known: known.map((k) => ({ selector: k.selector, signature: k.signature })),
        resolved: Object.entries(resolved).filter(([, v]) => v).map(([sel, sig]) => ({ selector: sel, signature: sig })),
      },
      dangerous,
      opcodeSignals: {
        hasDelegateCall: dis.hasDelegateCall,
        hasSelfdestruct: dis.hasSelfdestruct,
        hasCreate: dis.hasCreate,
        hasCreate2: dis.hasCreate2,
      },
    }, (key, value) => typeof value === "bigint" ? value.toString() : value, 2));
    return;
  }

  // --- Human-readable report ---
  const lines = [];
  const br = () => lines.push("");
  const sep = () => lines.push("  " + "─".repeat(56));

  lines.push("");
  lines.push("  ╔══════════════════════════════════════════════════════╗");
  lines.push("  ║   PHAROS CONTRACT INSPECTOR — ABI-Free Report       ║");
  lines.push("  ╚══════════════════════════════════════════════════════╝");
  br();
  lines.push(`  Address:   ${opts.addr}`);
  lines.push(`  Network:   ${net.name} (chainId ${net.chainId})`);
  lines.push(`  Bytecode:  ${dis.codeSize} bytes`);
  br();

  // Proxy
  sep();
  lines.push("  PROXY STATUS");
  sep();
  if (proxy.isProxy) {
    lines.push(`  ⚠️  PROXY DETECTED — ${proxy.type}`);
    lines.push(`  Implementation: ${proxy.impl}`);
    if (proxy.admin) lines.push(`  Admin:          ${proxy.admin}`);
  } else {
    lines.push(`  Not a proxy (direct deployment)`);
  }
  br();

  // Metadata
  sep();
  lines.push("  CONTRACT METADATA (live eth_call)");
  sep();
  if (meta.name)        lines.push(`  Name:         ${meta.name}`);
  if (meta.symbol)      lines.push(`  Symbol:       ${meta.symbol}`);
  if (meta.decimals != null) lines.push(`  Decimals:     ${meta.decimals}`);
  if (meta.totalSupply != null) {
    const d = meta.decimals || 18;
    const human = Number(meta.totalSupply) / Math.pow(10, d);
    lines.push(`  Total Supply: ${human.toLocaleString()} (${meta.totalSupply})`);
  }
  if (meta.owner)       lines.push(`  Owner:        ${meta.owner}`);
  br();

  // Standards
  if (standards.length) {
    sep();
    lines.push("  DETECTED STANDARDS");
    sep();
    for (const s of standards) lines.push(`  ✓ ${s}`);
    br();
  }

  // Selector inventory
  sep();
  lines.push("  FUNCTION SELECTOR INVENTORY");
  sep();
  lines.push(`  Extracted from bytecode:  ${dis.selectors.length} selectors`);
  lines.push(`  Matched to known sigs:    ${known.length}`);
  lines.push(`  Unknown (need 4byte/ABI): ${unknown.length}`);
  br();

  if (known.length > 0) {
    lines.push("  KNOWN FUNCTIONS");
    lines.push("");
    for (const k of known) {
      const flag = PRIVILEGED[k.selector] ? " ⚠️" : "";
      lines.push(`  ${k.selector}  ${k.signature}${flag}`);
    }
    br();
  }

  // Resolved unknowns
  const resolvedEntries = Object.entries(resolved).filter(([, v]) => v);
  if (resolvedEntries.length > 0) {
    lines.push("  RESOLVED (via 4byte.directory)");
    lines.push("");
    for (const [sel, sig] of resolvedEntries) {
      lines.push(`  ${sel}  ${sig}`);
    }
    br();
  }

  // Remaining truly unknown
  const stillUnknown = unknown.filter((s) => !resolved[s]);
  if (stillUnknown.length > 0) {
    lines.push("  UNRESOLVED SELECTORS");
    lines.push("");
    for (const s of stillUnknown) lines.push(`  ${s}`);
    br();
  }

  // Privileged / danger
  if (dangerous.length > 0 || dis.hasDelegateCall || dis.hasSelfdestruct) {
    sep();
    lines.push("  ⚠️  PRIVILEGED / DANGEROUS FUNCTIONS");
    sep();
    for (const d of dangerous) {
      lines.push(`  🚩 ${d.selector}  ${d.signature || d.reason}`);
      lines.push(`     Reason: ${d.reason}`);
    }
    if (dis.hasDelegateCall) lines.push("  🚩 DELEGATECALL opcode present in bytecode (proxy/arbitrary call risk)");
    if (dis.hasSelfdestruct) lines.push("  🚩 SELFDESTRUCT opcode present in bytecode (can destroy the contract)");
    if (dis.hasCreate)       lines.push("  ⚡ CREATE opcode present (factory — deploys new contracts)");
    if (dis.hasCreate2)      lines.push("  ⚡ CREATE2 opcode present (factory — deterministic deployment)");
    br();
  }

  // Implementation deep-dive (for proxies)
  if (implDis && implDis.selectors.length > 0) {
    sep();
    lines.push("  IMPLEMENTATION CONTRACT ANALYSIS");
    sep();
    lines.push(`  Impl address:  ${proxy.impl}`);
    lines.push(`  Impl bytecode: ${implDis.codeSize} bytes`);
    lines.push(`  Impl selectors: ${implDis.selectors.length}`);
    const implKnown = implDis.selectors.filter((s) => KNOWN[s]);
    const implPriv = implDis.selectors.filter((s) => PRIVILEGED[s]);
    if (implPriv.length > 0) {
      lines.push("");
      lines.push("  Privileged functions IN IMPLEMENTATION:");
      for (const s of implPriv) {
        lines.push(`  🚩 ${s}  ${KNOWN[s] || PRIVILEGED[s]}`);
      }
    }
    if (implKnown.length > 0) {
      lines.push("");
      lines.push("  All known implementation functions:");
      for (const s of implKnown) lines.push(`    ${s}  ${KNOWN[s]}`);
    }
    br();
  }

  sep();
  lines.push("  END OF REPORT");
  sep();
  br();

  console.log(lines.join("\n"));
}

main().catch((e) => {
  console.error(`Error: ${e.message}`);
  process.exit(1);
});
