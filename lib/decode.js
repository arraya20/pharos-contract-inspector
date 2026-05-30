// decode.js — decode standard contract metadata via eth_call, ABI-free.
// Uses ethers AbiCoder for correctness on dynamic types.

import { AbiCoder } from "ethers";

const abi = AbiCoder.defaultAbiCoder();

function decodeString(hex) {
  if (!hex || hex === "0x") return null;
  try {
    return abi.decode(["string"], hex)[0];
  } catch {
    // Some old tokens (e.g. MKR) return bytes32 instead of string.
    try {
      const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
      const bytes = Buffer.from(raw, "hex");
      const s = bytes.toString("utf8").replace(/\u0000+$/g, "").replace(/[^\x20-\x7e]/g, "");
      return s || null;
    } catch {
      return null;
    }
  }
}

function decodeUint(hex) {
  if (!hex || hex === "0x") return null;
  try {
    return abi.decode(["uint256"], hex)[0];
  } catch {
    return null;
  }
}

function decodeAddress(hex) {
  if (!hex || hex === "0x") return null;
  try {
    return abi.decode(["address"], hex)[0];
  } catch {
    return null;
  }
}

/**
 * Pull common metadata. Each is best-effort; missing fields are null.
 * Returns { name, symbol, decimals, totalSupply, owner }.
 */
export async function readMetadata(rpc, addr) {
  const out = { name: null, symbol: null, decimals: null, totalSupply: null, owner: null };

  const [name, symbol, decimals, supply, owner] = await Promise.all([
    rpc.ethCallSafe(addr, "0x06fdde03"), // name()
    rpc.ethCallSafe(addr, "0x95d89b41"), // symbol()
    rpc.ethCallSafe(addr, "0x313ce567"), // decimals()
    rpc.ethCallSafe(addr, "0x18160ddd"), // totalSupply()
    rpc.ethCallSafe(addr, "0x8da5cb5b"), // owner()
  ]);

  if (name.ok) out.name = decodeString(name.data);
  if (symbol.ok) out.symbol = decodeString(symbol.data);
  if (decimals.ok) {
    const d = decodeUint(decimals.data);
    out.decimals = d === null ? null : Number(d);
  }
  if (supply.ok) out.totalSupply = decodeUint(supply.data);
  if (owner.ok) out.owner = decodeAddress(owner.data);

  return out;
}

/**
 * Probe ERC-165 supportsInterface for a list of interface IDs.
 * Returns array of { id, name, supported }.
 */
export async function probeInterfaces(rpc, addr, interfaceIds) {
  const results = [];
  for (const [id, name] of Object.entries(interfaceIds)) {
    // supportsInterface(bytes4) selector 0x01ffc9a7 + padded interfaceId
    const data = "0x01ffc9a7" + id.slice(2).padEnd(64, "0");
    const res = await rpc.ethCallSafe(addr, data);
    let supported = false;
    if (res.ok && res.data && res.data !== "0x") {
      supported = /1$/.test(res.data.replace(/0+$/, "")) || /0{63}1$/.test(res.data.slice(2));
      // robust: last byte == 01
      supported = res.data.slice(-2) === "01";
    }
    results.push({ id, name, supported });
  }
  return results;
}
