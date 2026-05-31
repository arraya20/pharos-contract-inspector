#!/usr/bin/env node
import assert from "node:assert/strict";
import { assessRisk } from "./lib/risk.js";

function base(overrides = {}) {
  return {
    proxy: { isProxy: false, type: null, impl: null, admin: null },
    dis: { hasDelegateCall: false, hasSelfdestruct: false, hasCreate: false, hasCreate2: false, selectors: [] },
    implDis: null,
    dangerous: [],
    standards: [],
    meta: { name: null, symbol: null, decimals: null, totalSupply: null, owner: null },
    ...overrides,
  };
}

{
  const r = assessRisk(base({ standards: ["ERC-20"], meta: { owner: null } }));
  assert.equal(r.level, "Low");
  assert.ok(r.score < 40);
}

{
  const r = assessRisk(base({
    proxy: { isProxy: true, type: "OZ legacy proxy", impl: "0x1111111111111111111111111111111111111111", admin: null },
    dis: { hasDelegateCall: true, hasSelfdestruct: false, hasCreate: false, hasCreate2: false, selectors: ["0x3659cfe6"] },
    implDis: { hasDelegateCall: false, hasSelfdestruct: false, hasCreate: false, hasCreate2: false, selectors: ["0x40c10f19", "0x8456cb59", "0xf2fde38b"] },
    dangerous: [{ selector: "0x3659cfe6", reason: "upgradeTo (logic swap)" }],
    meta: { owner: "0x2222222222222222222222222222222222222222" },
  }));
  assert.equal(r.level, "High");
  assert.ok(r.score >= 70);
  assert.ok(r.flags.some((f) => f.check.includes("Proxy")));
  assert.ok(r.flags.some((f) => f.check.includes("Privileged selectors")));
}

{
  const r = assessRisk(base({
    dis: { hasDelegateCall: false, hasSelfdestruct: true, hasCreate: true, hasCreate2: false, selectors: [] },
  }));
  assert.equal(r.level, "Medium");
  assert.ok(r.flags.some((f) => f.check.includes("SELFDESTRUCT")));
}

{
  const r = assessRisk(base({
    resolvedFunctions: [
      { selector: "0x87517c45", signature: "approve(address,address,uint160,uint48)" },
      { selector: "0x36c78516", signature: "transferFrom(address,address,uint160,address)" },
      { selector: "0x2b67b570", signature: "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)" },
    ],
  }));
  assert.equal(r.level, "Medium");
  assert.ok(r.flags.some((f) => f.check.includes("Value-moving selectors")));
}

{
  const r = assessRisk(base({
    unresolvedSelectors: Array.from({ length: 15 }, (_, i) => `0x${String(i).padStart(8, "0")}`),
  }));
  assert.equal(r.level, "Medium");
  assert.ok(r.flags.some((f) => f.check.includes("Unresolved selectors")));
}

console.log("risk tests passed");
