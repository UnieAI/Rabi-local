/**
 * gen-manifests.ts —— 產生 Go 版自動更新的 testdata。
 *
 * 這裡的 manifest **是 TS 那一側真的簽出來的**：簽章輸入、base64url 編碼、
 * token 前綴、欄位形狀全部 import 自 runtime/apps/ava-local/src/release-verify.ts
 * （也就是 daemon 與 app 共用的那一份），簽的流程照抄 scripts/sign-ava-release.ts。
 *
 * 唯一的差別是**鑰匙**：真正的私鑰只在簽章機器上，所以這裡現場產兩把測試用的
 * 金鑰（A＝「我們的」、B＝「別人的」）。也因為這樣，這個檔不能直接用
 * scripts/sign-ava-release.ts —— 那支會拿編進程式的正式公鑰驗自己的產出，
 * 用測試金鑰簽必然被它擋下來（那正是它該有的行為）。
 *
 * 產出寫回這個資料夾，Go 測試直接讀：
 *
 *   bun run desktop/internal/update/testdata/gen-manifests.ts
 */
import { createHash, generateKeyPairSync, sign } from "node:crypto"
import { readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

import {
  AVA_RELEASE_TOKEN_PREFIX,
  base64Url,
  releaseSigningInput,
  verifyReleaseManifest,
  type ReleaseArtifact,
} from "../../../../runtime/apps/ava-local/src/release-verify"

const here = path.dirname(fileURLToPath(import.meta.url))

const keyA = generateKeyPairSync("ed25519")
const keyB = generateKeyPairSync("ed25519")
const pemA = keyA.publicKey.export({ type: "spki", format: "pem" }).toString().trim()
const pemB = keyB.publicKey.export({ type: "spki", format: "pem" }).toString().trim()
writeFileSync(path.join(here, "public-key-a.pem"), pemA + "\n")
writeFileSync(path.join(here, "public-key-b.pem"), pemB + "\n")

/**
 * 這兩份「執行檔」在測試裡會被真的下載、真的換上去、真的執行。
 *
 *   good —— `version` 報得出版本（過冒煙測試），沒帶參數就活著（接手成功）
 *   dies —— `version` 也報得出版本（**過得了冒煙測試**），但真的跑起來馬上死掉
 *
 * 第二份是回滾測試的主角：一個壞掉的版本不會好心地在冒煙測試那一關就露餡，
 * 它會在換過去之後才死，那正是「退回舊版」存在的理由。
 */
function daemonScript(version: string, body: string): string {
  return ["#!/bin/sh", `if [ "$1" = "version" ]; then echo ${version}; exit 0; fi`, body, ""].join("\n")
}
writeFileSync(path.join(here, "artifact-linux-x64"), daemonScript("0.2.0", "sleep 5"), { mode: 0o755 })
writeFileSync(path.join(here, "artifact-linux-x64-dies"), daemonScript("0.2.1", "exit 3"), { mode: 0o755 })

function artifactOf(bytes: Buffer, file: string): ReleaseArtifact {
  return { file, size: bytes.byteLength, sha256: createHash("sha256").update(bytes).digest("hex") }
}

const artifacts: Record<string, ReleaseArtifact> = {
  "linux-x64": artifactOf(readFileSync(path.join(here, "artifact-linux-x64")), "ava-local-linux-x64"),
  "darwin-arm64": artifactOf(Buffer.from("darwin build placeholder\n"), "ava-local-darwin-arm64"),
  "windows-x64": artifactOf(Buffer.from("windows build placeholder\n"), "ava-local-windows-x64.exe"),
}
/** 0.2.1 的 linux 檔換成那份「換過去就死」的，其餘平台沿用。 */
const diesArtifacts: Record<string, ReleaseArtifact> = {
  ...artifacts,
  "linux-x64": artifactOf(readFileSync(path.join(here, "artifact-linux-x64-dies")), "ava-local-linux-x64"),
}

const NOTES = "・換檔失敗會自己退回舊版\n・更新說明跟版本一起被簽章蓋住"

/** 照 scripts/sign-ava-release.ts：payload → base64url → Ed25519 簽 → 三段拼起來。 */
function signToken(payload: Record<string, unknown>, key: import("node:crypto").KeyObject): string {
  const payloadPart = base64Url(JSON.stringify(payload))
  const signaturePart = base64Url(sign(null, releaseSigningInput(payloadPart), key))
  return `${AVA_RELEASE_TOKEN_PREFIX}.${payloadPart}.${signaturePart}`
}

function payloadOf(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    version: "0.2.0",
    released: "2026-09-11T00:00:00.000Z",
    notes: NOTES,
    artifacts,
    ...extra,
  }
}

/** 竄改：payload 改掉、**簽章原封不動**（攻擊者拿不到私鑰，只能這樣做）。 */
function tamper(token: string, mutate: (p: Record<string, unknown>) => void): string {
  const [prefix, payloadPart, signaturePart] = token.split(".")
  const payload = JSON.parse(Buffer.from(payloadPart!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"))
  mutate(payload)
  return `${prefix}.${base64Url(JSON.stringify(payload))}.${signaturePart}`
}

const good = signToken(payloadOf(), keyA.privateKey)
const files: Record<string, string> = {
  // 好的那一份：A 簽的、欄位齊全。
  "good.manifest": good,
  // 同樣是 A 簽的，但版本比 daemon 現在的還舊 —— 不准降版。
  "old.manifest": signToken(payloadOf({ version: "0.0.9" }), keyA.privateKey),
  // 換過去就死的 0.2.1 —— 回滾那條路要有東西可以跑。
  "dies.manifest": signToken(payloadOf({ version: "0.2.1", artifacts: diesArtifacts }), keyA.privateKey),
  // 要求先升到 0.2.0 才換得過去。
  "min-version.manifest": signToken(payloadOf({ version: "0.3.0", minVersion: "0.2.0" }), keyA.privateKey),
  // **別人的鑰匙簽的** —— 形狀完全正確，就是不是我們發的。
  "other-key.manifest": signToken(payloadOf(), keyB.privateKey),
  // 只改了更新說明。使用者是看著那段字按下更新的，所以這一份必須驗不過。
  "tampered-notes.manifest": tamper(good, (p) => {
    p.notes = "・只是修了一個小錯字（其實不是）"
  }),
  // 只改了 sha256 —— 掉包位元組的唯一辦法。
  "tampered-sha256.manifest": tamper(good, (p) => {
    ;(p.artifacts as Record<string, ReleaseArtifact>)["linux-x64"]!.sha256 = "b".repeat(64)
  }),
}

for (const [name, token] of Object.entries(files)) {
  writeFileSync(path.join(here, name), token + "\n")
}

/* 產出自己先過一次 TS 的驗證器，Go 那邊才有資格說「跟 TS 同一個答案」。 */
const expect: Record<string, boolean> = {
  "good.manifest": true,
  "old.manifest": true,
  "dies.manifest": true,
  "min-version.manifest": true,
  "other-key.manifest": false,
  "tampered-notes.manifest": false,
  "tampered-sha256.manifest": false,
}
for (const [name, token] of Object.entries(files)) {
  const r = verifyReleaseManifest(token, pemA)
  if (r.ok !== expect[name]) {
    console.error(`${name}：TS 驗證器說 ok=${r.ok}，預期 ${expect[name]}`)
    process.exit(1)
  }
  console.log(`  ${name.padEnd(26)} ok=${r.ok}${r.ok ? ` version=${r.manifest.version}` : ` （${r.reason}）`}`)
}
console.log("\ntestdata 已更新，而且每一份都在 TS 的驗證器上得到預期的答案。")
