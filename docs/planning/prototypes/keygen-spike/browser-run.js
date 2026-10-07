// The browser half's harness, as run 2026-10-05.
//
// This is the script that was executed against the page, not a re-enactment. It needs the
// browser tool's script runner (the session that ran it had one); a plain node process
// cannot drive the page, so the runner is part of the environment rather than this file.
//
// It opens the page, listens to every request the tab makes, generates a key, checks that
// key, checks a key made by GnuPG that advertises AEAD, and returns the evidence.
//
// pass it as: tab.run(run, { args: [aeadArmor] })

export async function run({ page }, aeadArmor) {
  const requests = [];
  page.on("request", (r) => requests.push(r.url()));
  await page.goto("http://127.0.0.1:8899/index.html", { waitUntil: "networkidle0" });
  await page.waitForFunction(() => window.__keygen && window.__keygen.ready, { timeout: 30000 });

  const generated = await page.evaluate(() => window.__keygen.generate());
  const clean = await page.evaluate((a) => window.__keygen.check(a), generated.publicArmor);
  const flagged = await page.evaluate((a) => window.__keygen.check(a), aeadArmor);
  const claimed = await page.evaluate(() =>
    performance.getEntriesByType("resource").map((r) => r.name));

  const local = (u) => u.startsWith("http://127.0.0.1:8899/");
  return {
    everyRequestLocal: requests.every(local),
    requests,
    pageClaims: claimed,
    fingerprint: generated.fingerprint,
    selfCheck: clean,
    aeadKeyCheck: flagged,
  };
}
