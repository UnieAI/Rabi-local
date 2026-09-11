package update

// PublicKeyPEM 是驗證更新檔的 Ed25519 **公鑰**，跟 TS 版共用同一把
// （runtime/apps/ava-local/src/release-public-key.ts）。同一把鑰匙的意思是：
// 同一份簽好的 latest.manifest，TS daemon 與這一版都認得。
//
// 對應的**私鑰不在這個 repo 裡**，也不在任何一台跑 app 的機器上：它在簽章
// 機器上（~/unieai-ava-local-release-signing-key.pem，0600），由
// scripts/sign-ava-release.ts 使用。
//
// 換鑰匙＝所有舊的 release manifest 立刻失效，使用者要重新下載一次執行檔，
// 而且**兩邊要同時換**（這個檔與 release-public-key.ts），否則會變成只有一半
// 的機器更新得了。所以換之前先想清楚。
const PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjMRlYuNVXq7v8UR14wKwen10rBcqRT9z5WiJiVs7xAM=
-----END PUBLIC KEY-----`
