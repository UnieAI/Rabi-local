/**
 * gen-vectors.mjs —— Go 版與 TS 版的差分測試語料，**由 TS 那一側跑出來**。
 *
 * ## 為什麼不是手寫一份期望值
 *
 * 手寫的期望值只證明「Go 符合我以為 TS 是怎樣的」。這支檔案直接 import
 * runtime/packages/ava-local-protocol/src/*.mjs，把 TS 自己那 21 條測試的語料
 * 重建一次，然後**執行 TS 的實作**、記下它真正給出的判斷。Go 那邊
 * （vectors_test.go）讀同一份 vectors.json，要給出同一個判斷。
 *
 * ## 兩個方向都要跑得動
 *
 *   node gen-vectors.mjs            重新產生 vectors.json（金鑰是新的，會整份變動）
 *   node gen-vectors.mjs --verify   拿**已提交的** vectors.json 再餵 TS 一次
 *
 * `--verify` 才是差分的那一半：同一組輸入（committed），TS 現在的行為必須跟
 * 當初記下來的一致。TS 那邊改了規則而忘記同步 Go，這一步會紅。
 *
 * ## 語料哪裡來
 *
 *   · device-approval.test.mjs 的 9 條
 *   · device-enrollment.test.mjs 的 12 條
 *   · device-approval-wired.test.ts 裡屬於協定層的那幾條（票的前綴、重放、
 *     換掉指令）
 *   · 加上一組**寬鬆解碼**的邊界（壞掉的 base64、exp 是字串、v 是 "1"）——
 *     這些是 Go 與 Node 最容易分歧的地方，而分歧的症狀是「同一張票兩個
 *     daemon 給不同的拒絕理由」。
 */
import { createHash, createSign, generateKeyPairSync, randomUUID, sign as rawSign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROTO = path.resolve(HERE, "../../../../runtime/packages/ava-local-protocol/src");

const { encodeDeviceClaims, challengeFor, verifyDeviceApproval, DEVICE_APPROVAL_TTL_MS } = await import(
  path.join(PROTO, "device-approval.mjs")
);
const { encodeEnrollment, enrollmentChallenge, verifyEnrollment } = await import(path.join(PROTO, "device-enrollment.mjs"));
const { isDeviceTicket, packDeviceTicket, parseDeviceTicket } = await import(path.join(PROTO, "device-ticket.mjs"));
const { mintApprovalToken } = await import(path.join(PROTO, "approval.mjs"));

const OUT = path.join(HERE, "vectors.json");
const b64url = (b) => Buffer.from(b).toString("base64url");
const sha256 = (b) => createHash("sha256").update(b).digest();

/** 一把假的 passkey。瀏覽器的 getPublicKey() 給的就是 SPKI。 */
function makeCredential() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { id: randomUUID(), publicKey, privateKey };
}

/** 模擬驗證器：簽 authenticatorData || sha256(clientDataJSON)。 */
function assertWith(cred, challenge, { up = true } = {}) {
  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: "webauthn.get", challenge, origin: "https://agent.dev.unieai.com" }),
  );
  const authData = Buffer.alloc(37);
  sha256(Buffer.from("rpid")).copy(authData, 0);
  authData[32] = up ? 0x01 : 0x00;
  const s = createSign("sha256");
  s.update(Buffer.concat([authData, sha256(clientDataJSON)]));
  s.end();
  return {
    credentialId: cred.id,
    authenticatorData: b64url(authData),
    clientDataJSON: b64url(clientDataJSON),
    signature: b64url(s.sign(cred.privateKey)),
  };
}

/**
 * 語料裡的「現在」一律**釘死**。
 *
 * 第一版用了 Date.now()：產生的那一刻全綠，五分鐘之後（票的 TTL）整批變成
 * expired，而失敗的訊息會說「Go 跟 TS 不一樣」—— 一個跟真正的原因完全無關
 * 的句子。差分語料裡不可以有任何一個會隨時間改變的輸入。
 */
const FIXED = 1_700_000_000_000;

const keysOf = (...creds) => Object.fromEntries(creds.map((c) => [c.id, c.publicKey]));
const CLAIMS = { invokeId: "act-1", machineId: "m-1", tool: "exec", payloadHash: "ph-1", iat: FIXED };
const EXPECT = { machineId: "m-1", tool: "exec", payloadHash: "ph-1" };
const MID = "m-1";

// ─────────────────────────────────────────────────────────────────────────
// 語料（只有輸入；判斷由 runApproval / runEnrollment / runTicket 現場跑出來）
// ─────────────────────────────────────────────────────────────────────────

function approvalCases() {
  const out = [];
  const add = (name, v) => out.push({ name, runs: 1, now: FIXED, useNonces: false, ...v });

  {
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    add("使用者裝置簽的核准驗得過", { claimsB64: c, assertion: assertWith(cred, challengeFor(c)), expect: EXPECT, keys: keysOf(cred) });
  }
  {
    // **雲端沒有私鑰，所以偽造不出來** —— 這是整個方案的重點
    const real = makeCredential();
    const attacker = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    const forged = assertWith(attacker, challengeFor(c));
    forged.credentialId = real.id; // 冒用使用者註冊過的 credentialId
    add("被攻破的 app 用自己的私鑰簽、冒用使用者的 credentialId", {
      claimsB64: c,
      assertion: forged,
      expect: EXPECT,
      keys: keysOf(real),
    });
  }
  {
    // 沒註冊過的憑證一律不認 —— 雲端不能自己加一把公鑰
    const other = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    add("沒註冊過的憑證一律不認", { claimsB64: c, assertion: assertWith(other, challengeFor(c)), expect: EXPECT, keys: keysOf(makeCredential()) });
  }
  {
    // 規則 2：雲端在 frame 上自帶公鑰也沒有用 —— 信任清單是唯一的金鑰來源。
    // 這裡把攻擊者的公鑰塞進 assertion 物件的額外欄位，keys 仍然只有使用者那把。
    const user = makeCredential();
    const attacker = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    const a = assertWith(attacker, challengeFor(c));
    a.publicKey = attacker.publicKey; // 線路上自帶的公鑰
    add("雲端在票上自帶公鑰 —— 不可以被讀到", { claimsB64: c, assertion: a, expect: EXPECT, keys: keysOf(user) });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    add("換了指令就對不上", { claimsB64: c, assertion: assertWith(cred, challengeFor(c)), expect: { ...EXPECT, payloadHash: "ph-2" }, keys: keysOf(cred) });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    add("拿別處取得的合法 assertion 來用", {
      claimsB64: c,
      assertion: assertWith(cred, b64url(Buffer.from("別的東西"))),
      expect: EXPECT,
      keys: keysOf(cred),
    });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims({ ...CLAIMS, machineId: "m-2" });
    add("別台機器的票不能用在這一台", { claimsB64: c, assertion: assertWith(cred, challengeFor(c)), expect: EXPECT, keys: keysOf(cred) });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims({ ...CLAIMS, tool: "writeFile" });
    add("換了工具也對不上", { claimsB64: c, assertion: assertWith(cred, challengeFor(c)), expect: EXPECT, keys: keysOf(cred) });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims({ ...CLAIMS, iat: 1000, exp: 2000 });
    add("過期的不收", { claimsB64: c, assertion: assertWith(cred, challengeFor(c)), expect: EXPECT, keys: keysOf(cred), now: 3000 });
  }
  {
    const cred = makeCredential();
    const now = FIXED;
    const c = encodeDeviceClaims({ ...CLAIMS, iat: now + 600_000, exp: now + 900_000 });
    add("未來的票也不收", { claimsB64: c, assertion: assertWith(cred, challengeFor(c)), expect: EXPECT, keys: keysOf(cred), now });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    add("使用者不在場（UP 沒亮）不算同意", { claimsB64: c, assertion: assertWith(cred, challengeFor(c), { up: false }), expect: EXPECT, keys: keysOf(cred) });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    add("同一張票不能用第二次", { claimsB64: c, assertion: assertWith(cred, challengeFor(c)), expect: EXPECT, keys: keysOf(cred), useNonces: true, runs: 2 });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    const a = assertWith(cred, challengeFor(c));
    a.clientDataJSON = b64url(Buffer.from("{不是 JSON"));
    add("clientDataJSON 不是 JSON", { claimsB64: c, assertion: a, expect: EXPECT, keys: keysOf(cred) });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: challengeFor(c) }));
    const a = assertWith(cred, challengeFor(c));
    a.clientDataJSON = b64url(clientDataJSON);
    add("註冊儀式的 assertion 不能拿來核准", { claimsB64: c, assertion: a, expect: EXPECT, keys: keysOf(cred) });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    const a = assertWith(cred, challengeFor(c));
    a.signature = b64url(Buffer.from("這不是簽章"));
    add("簽章是垃圾", { claimsB64: c, assertion: a, expect: EXPECT, keys: keysOf(cred) });
  }
  {
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    const a = assertWith(cred, challengeFor(c));
    a.authenticatorData = b64url(Buffer.alloc(10)); // 太短，讀不到 flags
    add("authenticatorData 太短", { claimsB64: c, assertion: a, expect: EXPECT, keys: keysOf(cred) });
  }
  {
    // 信任清單裡那把根本不是金鑰（例如註冊的時候塞進去一串垃圾）
    const cred = makeCredential();
    const c = encodeDeviceClaims(CLAIMS);
    add("清單上那把不是金鑰", { claimsB64: c, assertion: assertWith(cred, challengeFor(c)), expect: EXPECT, keys: { [cred.id]: "-----BEGIN PUBLIC KEY-----\nbm90LWEta2V5\n-----END PUBLIC KEY-----\n" } });
  }
  {
    // Ed25519：Node 的 createVerify("sha256") 對它會丟例外 → bad_key。
    // Go 的標準庫驗得動，所以這一條是**逼 Go 跟著回 bad_key** 的那一條。
    const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const cred = { id: randomUUID(), publicKey, privateKey };
    const c = encodeDeviceClaims(CLAIMS);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: challengeFor(c) }));
    const authData = Buffer.alloc(37);
    authData[32] = 0x01;
    const sig = rawSign(null, Buffer.concat([authData, sha256(clientDataJSON)]), privateKey);
    add("Ed25519 在 sha256 那條路上用不了", {
      claimsB64: c,
      assertion: { credentialId: cred.id, authenticatorData: b64url(authData), clientDataJSON: b64url(clientDataJSON), signature: b64url(sig) },
      expect: EXPECT,
      keys: keysOf(cred),
    });
  }

  // ── 寬鬆解碼／型別的邊界 ────────────────────────────────────────────
  const cred = makeCredential();
  const rawClaims = (obj) => b64url(Buffer.from(JSON.stringify(obj)));
  const bare = (c) => ({ claimsB64: c, assertion: assertWith(cred, challengeFor(c)), expect: EXPECT, keys: keysOf(cred) });
  add("claims 不是合法 base64/JSON", bare("%%%不是東西%%%"));
  add("claims 是 JSON 但不是物件", bare(rawClaims(42)));
  add("claims 是 null", bare(rawClaims(null)));
  add("v 是字串 \"1\"", bare(rawClaims({ ...CLAIMS, v: "1", alg: "webauthn", exp: FIXED + 60_000 })));
  add("alg 不是 webauthn", bare(rawClaims({ ...CLAIMS, v: 1, alg: "hmac", exp: FIXED + 60_000 })));
  add("exp 是字串", bare(rawClaims({ ...CLAIMS, v: 1, alg: "webauthn", exp: "9999999999999" })));
  add("exp 大到變成 Infinity", bare(rawClaims({ ...CLAIMS, v: 1, alg: "webauthn", exp: 1e400 })));
  add("exp 不存在", bare(rawClaims({ ...CLAIMS, v: 1, alg: "webauthn" })));
  add("machineId 是數字", bare(rawClaims({ ...CLAIMS, v: 1, alg: "webauthn", machineId: 1, exp: FIXED + 60_000 })));
  {
    const c = encodeDeviceClaims(CLAIMS);
    const dirty = c.slice(0, 8) + "!!" + c.slice(8);
    // challenge 綁的是**原始字串**，所以夾垃圾之後 challenge 一定對不上 ——
    // 這一條要的就是「Go 不可以因為解不開而回 claims_unreadable」。
    add("claims 字串被夾入垃圾字元", { claimsB64: dirty, assertion: assertWith(cred, challengeFor(c)), expect: EXPECT, keys: keysOf(cred) });
  }
  return out;
}

function enrollmentCases() {
  const out = [];
  const add = (name, v) => out.push({ name, by: null, localConfirm: false, now: FIXED, machineId: MID, ...v });
  const addReq = (cred, over = {}) =>
    encodeEnrollment({ op: "add", machineId: MID, credentialId: cred.id, publicKey: cred.publicKey, iat: FIXED, ...over });

  {
    const first = makeCredential();
    add("第一把：人就在那台電腦前面，本機確認就算數", { enrollment: addReq(first), keys: {}, localConfirm: true });
  }
  {
    const existing = makeCredential();
    const attacker = makeCredential();
    add("已經有金鑰之後，本機確認不再是捷徑", { enrollment: addReq(attacker), keys: keysOf(existing), localConfirm: true });
  }
  {
    // **被攻破的雲端加不進自己的金鑰** —— 這是整支檔案的重點
    const user = makeCredential();
    const attacker = makeCredential();
    const req = addReq(attacker);
    add("雲端自產一把、自己簽自己進來", { enrollment: req, by: assertWith(attacker, enrollmentChallenge(req)), keys: keysOf(user) });
  }
  {
    const user = makeCredential();
    const attacker = makeCredential();
    const req = addReq(attacker);
    const forged = assertWith(attacker, enrollmentChallenge(req));
    forged.credentialId = user.id;
    add("拿已信任的 id 但用別的私鑰簽", { enrollment: req, by: forged, keys: keysOf(user) });
  }
  {
    const laptop = makeCredential();
    const phone = makeCredential();
    const req = addReq(phone, { label: "手機" });
    add("已信任的裝置可以加第二把", { enrollment: req, by: assertWith(laptop, enrollmentChallenge(req)), keys: keysOf(laptop) });
  }
  {
    const me = makeCredential();
    const req = addReq(me);
    add("不可以自己簽自己進來", { enrollment: req, by: assertWith(me, enrollmentChallenge(req)), keys: keysOf(me) });
  }
  {
    const laptop = makeCredential();
    const phone = makeCredential();
    const req = encodeEnrollment({ op: "remove", machineId: MID, credentialId: phone.id, iat: FIXED });
    add("撤銷走本機確認不算數", { enrollment: req, keys: keysOf(laptop, phone), localConfirm: true });
    add("撤銷由已信任的裝置簽就算數", { enrollment: req, by: assertWith(laptop, enrollmentChallenge(req)), keys: keysOf(laptop, phone) });
  }
  {
    const cred = makeCredential();
    const req = encodeEnrollment({ op: "remove", machineId: MID, credentialId: cred.id, iat: FIXED });
    add("一把都沒有的時候，本機確認只能用來 add", { enrollment: req, keys: {}, localConfirm: true });
  }
  {
    const only = makeCredential();
    const req = encodeEnrollment({ op: "remove", machineId: MID, credentialId: only.id, iat: FIXED });
    add("不可以撤到一把都不剩", { enrollment: req, by: assertWith(only, enrollmentChallenge(req)), keys: keysOf(only) });
  }
  {
    const cred = makeCredential();
    add("別台機器的註冊請求不算數", { enrollment: addReq(cred, { machineId: "m-2" }), keys: {}, localConfirm: true });
  }
  {
    const cred = makeCredential();
    add("沒有簽也沒有本機確認", { enrollment: addReq(cred), keys: {} });
  }
  {
    const cred = makeCredential();
    add("註冊請求過期", { enrollment: addReq(cred, { iat: 1000, exp: 2000 }), keys: {}, localConfirm: true, now: 3000 });
  }
  {
    // 空的 by 物件＝「有給」，所以一定走簽章那條路，不可以掉進本機確認。
    const cred = makeCredential();
    add("by 是空物件，不可以被當成本機確認", {
      enrollment: addReq(cred),
      by: { credentialId: "", authenticatorData: "", clientDataJSON: "", signature: "" },
      keys: {},
      localConfirm: true,
    });
  }
  {
    const laptop = makeCredential();
    const phone = makeCredential();
    const req = addReq(phone);
    add("簽的是別的請求（challenge 對不上）", {
      enrollment: req,
      by: assertWith(laptop, enrollmentChallenge(addReq(makeCredential()))),
      keys: keysOf(laptop),
    });
  }
  {
    const laptop = makeCredential();
    const phone = makeCredential();
    const req = addReq(phone);
    add("簽的人不在場（UP 沒亮）", { enrollment: req, by: assertWith(laptop, enrollmentChallenge(req), { up: false }), keys: keysOf(laptop) });
  }
  add("註冊請求讀不出來", { enrollment: "%%%", keys: {}, localConfirm: true });
  add("註冊請求版本不對", { enrollment: b64url(Buffer.from(JSON.stringify({ v: 2, op: "add", machineId: MID, credentialId: "x", exp: FIXED + 1000 }))), keys: {}, localConfirm: true });
  return out;
}

function ticketCases() {
  const cred = makeCredential();
  const c = encodeDeviceClaims(CLAIMS);
  const a = assertWith(cred, challengeFor(c));
  const good = packDeviceTicket(c, a);
  const hmac = mintApprovalToken("k".repeat(64), { invokeId: "act-1", machineId: MID, tool: "exec", payloadHash: "ph-1" });
  return [
    { name: "一張好的裝置票", token: good },
    { name: "HMAC 票不是裝置票（前綴撞不到）", token: hmac },
    { name: "空字串", token: "" },
    { name: "只有前綴", token: "ava1d." },
    { name: "沒有第二個點", token: "ava1d.abcdef" },
    { name: "點在最後", token: "ava1d.abcdef." },
    { name: "assertion 不是 JSON", token: "ava1d." + c + ".%%%" },
    { name: "assertion 是陣列", token: "ava1d." + c + "." + b64url(Buffer.from("[]")) },
    { name: "assertion 少一個欄位", token: "ava1d." + c + "." + b64url(Buffer.from(JSON.stringify({ credentialId: "a", authenticatorData: "b", clientDataJSON: "c" }))) },
    { name: "assertion 的欄位是空字串", token: "ava1d." + c + "." + b64url(Buffer.from(JSON.stringify({ credentialId: "a", authenticatorData: "b", clientDataJSON: "c", signature: "" }))) },
    { name: "assertion 的欄位不是字串", token: "ava1d." + c + "." + b64url(Buffer.from(JSON.stringify({ credentialId: 1, authenticatorData: "b", clientDataJSON: "c", signature: "d" }))) },
  ];
}

// ─────────────────────────────────────────────────────────────────────────
// 跑 TS 的實作，記下它真正給出的判斷
// ─────────────────────────────────────────────────────────────────────────

function runApproval(v) {
  const keys = new Map(Object.entries(v.keys));
  const seen = new Set();
  const nonces = v.useNonces ? { seen: (id) => seen.has(id), remember: (id) => seen.add(id) } : undefined;
  const runs = [];
  for (let i = 0; i < (v.runs ?? 1); i++) {
    const r = verifyDeviceApproval(v.claimsB64, v.assertion, v.expect, {
      keys,
      ...(v.now === null || v.now === undefined ? {} : { now: v.now }),
      ...(nonces ? { nonces } : {}),
    });
    runs.push(r.ok ? { ok: true, invokeId: r.claims.invokeId } : { ok: false, reason: r.reason });
  }
  return runs;
}

function runEnrollment(v) {
  const r = verifyEnrollment(v.enrollment, v.by, {
    machineId: v.machineId,
    keys: new Map(Object.entries(v.keys)),
    localConfirm: v.localConfirm,
    ...(v.now === null || v.now === undefined ? {} : { now: v.now }),
  });
  if (!r.ok) return { ok: false, reason: r.reason };
  return {
    ok: true,
    op: r.req.op,
    credentialId: r.req.credentialId,
    label: r.req.label ?? null,
  };
}

function runTicket(v) {
  const parsed = parseDeviceTicket(v.token);
  return { isDeviceTicket: isDeviceTicket(v.token), parsed: parsed ? { claimsB64: parsed.claimsB64, assertion: parsed.assertion } : null };
}

const sourceDigest = () =>
  Object.fromEntries(
    ["device-approval.mjs", "device-enrollment.mjs", "device-ticket.mjs"].map((f) => [
      f,
      createHash("sha256").update(readFileSync(path.join(PROTO, f))).digest("hex").slice(0, 16),
    ]),
  );

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

if (process.argv.includes("--verify")) {
  const doc = JSON.parse(readFileSync(OUT, "utf8"));
  let bad = 0;
  const check = (kind, list, run) => {
    for (const v of list) {
      const got = run(v);
      if (!same(got, v.result)) {
        bad++;
        console.error(`✗ [${kind}] ${v.name}\n  記下的：${JSON.stringify(v.result)}\n  現在的：${JSON.stringify(got)}`);
      }
    }
  };
  check("approval", doc.approval, runApproval);
  check("enrollment", doc.enrollment, runEnrollment);
  check("ticket", doc.ticket, runTicket);
  const n = doc.approval.length + doc.enrollment.length + doc.ticket.length;
  if (bad) {
    console.error(`\n${bad}/${n} 條語料上，TS 的行為跟 vectors.json 記下的不一樣。`);
    console.error("要嘛規則被改了（Go 那邊要跟著改），要嘛這份語料過期了（重跑 gen-vectors.mjs）。");
    process.exit(1);
  }
  const digest = sourceDigest();
  if (!same(digest, doc.source)) {
    console.error(`⚠ 協定原始碼變了（${JSON.stringify(doc.source)} → ${JSON.stringify(digest)}）但行為還一致。`);
  }
  console.log(`✓ TS 這一側 ${n} 條語料全部跟 vectors.json 一致（TTL=${DEVICE_APPROVAL_TTL_MS}ms）`);
} else {
  const doc = {
    note: "由 desktop/internal/devicekeys/testdata/gen-vectors.mjs 跑 TS 實作產生，請勿手改。",
    source: sourceDigest(),
    deviceApprovalTtlMs: DEVICE_APPROVAL_TTL_MS,
    approval: approvalCases().map((v) => ({ ...v, result: runApproval(v) })),
    enrollment: enrollmentCases().map((v) => ({ ...v, result: runEnrollment(v) })),
    ticket: ticketCases().map((v) => ({ ...v, result: runTicket(v) })),
  };
  writeFileSync(OUT, JSON.stringify(doc, null, 2) + "\n");
  console.log(`寫好 ${OUT}：approval ${doc.approval.length} / enrollment ${doc.enrollment.length} / ticket ${doc.ticket.length}`);
}
