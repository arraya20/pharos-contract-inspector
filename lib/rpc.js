// rpc.js — minimal JSON-RPC client over fetch (Node 18+ has global fetch).
// No ethers provider dependency for raw calls keeps this resilient to RPC quirks.

export class Rpc {
  constructor(url) {
    this.url = url;
    this.id = 0;
  }

  async call(method, params = []) {
    const body = JSON.stringify({ jsonrpc: "2.0", id: ++this.id, method, params });
    const res = await fetch(this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    if (!res.ok) throw new Error(`RPC HTTP ${res.status} for ${method}`);
    const json = await res.json();
    if (json.error) throw new Error(`RPC error ${json.error.code}: ${json.error.message}`);
    return json.result;
  }

  getCode(addr, block = "latest") {
    return this.call("eth_getCode", [addr, block]);
  }

  getStorageAt(addr, slot, block = "latest") {
    return this.call("eth_getStorageAt", [addr, slot, block]);
  }

  getBalance(addr, block = "latest") {
    return this.call("eth_getBalance", [addr, block]);
  }

  chainId() {
    return this.call("eth_chainId");
  }

  // eth_call that tolerates reverts: returns { ok, data } instead of throwing.
  async ethCallSafe(to, data, block = "latest") {
    try {
      const result = await this.call("eth_call", [{ to, data }, block]);
      return { ok: true, data: result };
    } catch (e) {
      return { ok: false, data: null, error: e.message };
    }
  }
}
