// rpc.js — minimal JSON-RPC client over fetch (Node 18+ has global fetch).
// No ethers provider dependency for raw calls keeps this resilient to RPC quirks.

export class Rpc {
  constructor(url, { timeoutMs = 12_000 } = {}) {
    this.url = url;
    this.id = 0;
    this.timeoutMs = timeoutMs;
  }

  async call(method, params = []) {
    const body = JSON.stringify({ jsonrpc: "2.0", id: ++this.id, method, params });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    let res;
    try {
      res = await fetch(this.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        signal: controller.signal,
      });
    } catch (e) {
      if (e?.name === "AbortError") throw new Error(`RPC timeout after ${this.timeoutMs}ms for ${method}`);
      throw e;
    } finally {
      clearTimeout(timeout);
    }
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
