// risk.js — lightweight deterministic risk scoring from introspection signals.
// Not an audit. This is a pre-flight safety summary for agents before calls.

export function assessRisk({ proxy, dis, implDis, dangerous, standards, meta }) {
  const flags = [];
  let score = 5;

  const add = (check, status, impact, details, evidence = []) => {
    score += impact;
    flags.push({ check, status, scoreImpact: impact, details, evidence });
  };

  if (proxy?.isProxy) {
    add("Proxy / upgradeability", "warn", 22, `${proxy.type} detected. Logic may change over time.`, [proxy.impl, proxy.admin].filter(Boolean));
  } else {
    add("Proxy / upgradeability", "pass", 0, "No proxy pattern detected by bytecode/storage/getter checks.");
  }

  const priv = new Set((dangerous || []).map((d) => d.selector));
  if (implDis?.selectors) {
    for (const s of implDis.selectors) {
      if (["0x3659cfe6", "0x4f1ef286", "0x40c10f19", "0x8456cb59", "0x3f4ba83a", "0xf2fde38b", "0x8f283970", "0x2f2ff15d", "0xd547741f"].includes(s)) priv.add(s);
    }
  }
  if (priv.size) {
    const impact = Math.min(30, 8 + priv.size * 5);
    add("Privileged selectors", "warn", impact, "Admin/supply/upgrade controls detected. Review authority before moving funds.", [...priv]);
  } else {
    add("Privileged selectors", "pass", 0, "No common privileged selectors detected.");
  }

  if (meta?.owner) {
    add("Owner/admin exposure", "warn", 12, "owner() returned a non-zero address.", [meta.owner]);
  }

  if (dis?.hasDelegateCall) add("DELEGATECALL opcode", "warn", 12, "Delegatecall present. Common in proxies, risky in arbitrary-call routers.");
  if (dis?.hasSelfdestruct || implDis?.hasSelfdestruct) add("SELFDESTRUCT opcode", "warn", 35, "Contract or implementation contains SELFDESTRUCT opcode.");
  if (dis?.hasCreate || dis?.hasCreate2 || implDis?.hasCreate || implDis?.hasCreate2) add("Factory behavior", "info", 8, "CREATE/CREATE2 opcode present; contract can deploy other contracts.");

  if ((standards || []).includes("ERC-20") && !meta?.owner && !proxy?.isProxy && !priv.size) {
    add("ERC-20 simplicity", "pass", -5, "ERC-20-like direct contract with no obvious admin getter/proxy signal.");
  }

  score = Math.max(0, Math.min(100, score));
  const level = score >= 70 ? "High" : score >= 40 ? "Medium" : "Low";
  const headline = level === "High"
    ? "High risk: review admin powers, upgradeability, and privileged selectors before interaction."
    : level === "Medium"
      ? "Medium risk: proceed with limits and verify trust assumptions."
      : "Low observed risk from ABI-free bytecode scan.";

  const recommendations = [
    "Treat this as pre-flight triage, not a full source-level audit.",
    "For value-moving actions, verify target address, decoded calldata, and spend limits before signing.",
    proxy?.isProxy ? "Monitor implementation address before each major interaction." : "Prefer verified source when available for final review.",
    priv.size ? "Identify who controls privileged functions before depositing or approving tokens." : "Still check custom roles not covered by common selector fingerprints."
  ];

  return { score, level, headline, flags, recommendations };
}
