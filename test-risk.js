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

console.log("risk tests passed");
