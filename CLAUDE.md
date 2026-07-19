# etzhayyim-project-vpn

SSoT: `90-docs/adr/2605252200-vpn-etzhayyim-design.md`

## Stack

| Component | 場所 | 役割 |
|---|---|---|
| portal (L1) | `appview/etzhayyim-vpn-portal/` | SvelteKit — vpn.etzhayyim.com アカウント管理 + .conf DL |
| provisioner (L8) | `provisioner/` | FastAPI pod — peer 登録 / config 生成 / agent 同期 |
| wg-agent | `wg-agent/` | exit node 上の systemd service — peer list 同期 |
| lexicons | `00-contracts/lexicons/ai/etzhayyim/apps/vpn/` | NSID 7本 |
| K8s | `50-infra/k8s/vpn-provisioner/` | VKE SJC Deployment |

## CRITICAL: No-logs 不変条件

`vertex_vpn_*` に接続ログ系カラムを追加しない。
`connected_at` / `source_ip` / `bytes_*` 系は schema・コード・ログの全レイヤーで禁止。
詳細: CLAUDE.md (root) §VPN No-logs 不変条件 + ADR §5。

## NSID

`ai.etzhayyim.apps.vpn.{provisionDevice,revokeDevice,listDevices,getServerList,rotateKey,downloadConfig,getSubscription}`

## Phase 0 (現在)

法務ゲート待ち。実装は lexicon JSON 作成から開始してよい。
本番 deploy は JP 電気通信事業法弁護士確認後。
