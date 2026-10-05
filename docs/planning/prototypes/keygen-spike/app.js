import init, { generate, check } from "./pkg/keygen_spike.js";

const $ = (id) => document.getElementById(id);
const nowSecs = () => Math.floor(Date.now() / 1000);

await init();

// The spike page is driven by a browser automation pass, which cannot reach into a module
// scope, so the two entry points are exposed deliberately. The real page would not do this.
window.__keygen = {
  ready: true,
  generate: (variant = "ed25519", userId = "Spike Member <spike@example.invalid>", passphrase = "spike-passphrase-not-a-secret") =>
    JSON.parse(generate(variant, userId, passphrase)),
  check: (armor) => JSON.parse(check(armor, nowSecs())),
};

$("gen").addEventListener("click", () => {
  const out = $("gen-out");
  out.innerHTML = "";
  const result = window.__keygen.generate();
  if (!result.ok) {
    out.textContent = `failed: ${result.error}`;
    return;
  }
  for (const [label, value] of [
    ["fingerprint", result.fingerprint],
    ["public key", result.publicArmor],
  ]) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    if (label === "public key") {
      const pre = document.createElement("pre");
      pre.textContent = value;
      dd.append(pre);
    } else {
      dd.textContent = value;
    }
    out.append(dt, dd);
  }
  const blob = new Blob([result.secretArmor], { type: "application/pgp-keys" });
  const link = $("download");
  link.href = URL.createObjectURL(blob);
  link.download = "spike-secret.asc";
  link.hidden = false;
});

$("chk").addEventListener("click", () => {
  const out = $("check-out");
  out.innerHTML = "";
  const result = window.__keygen.check($("armor").value);
  if (!result.ok && result.error) {
    out.innerHTML = `<li class="bad">${result.error}</li>`;
    return;
  }
  if (result.findings.length === 0) {
    out.innerHTML = '<li class="good">Clean. Encrypting to this key works.</li>';
    return;
  }
  for (const finding of result.findings) {
    const li = document.createElement("li");
    li.className = "bad";
    li.textContent = finding;
    out.append(li);
  }
});

for (const entry of performance.getEntriesByType("resource")) {
  const li = document.createElement("li");
  li.textContent = `${entry.initiatorType}: ${entry.name}`;
  $("resources").append(li);
}
