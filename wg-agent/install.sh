#!/usr/bin/env bash
# install.sh — exit node (Ubuntu 22.04) セットアップ
# TODO: 実行前に以下を環境変数またはプロンプトで設定してください
#   SERVER_PRIVATE_KEY  — wg genkey で生成したサーバー秘密鍵
#   WG_AGENT_SECRET     — provisioner と共有するシークレット (openssl rand -hex 32)
set -euo pipefail

# ── WireGuard ─────────────────────────────────────────────────────────────────
apt-get update -y
apt-get install -y wireguard wireguard-tools unbound python3 python3-pip

# ── Unbound DoH リゾルバ (no-logs 設定) ──────────────────────────────────────
cat > /etc/unbound/unbound.conf.d/vpn.conf << 'EOF'
server:
  interface: 10.8.0.1
  access-control: 10.8.0.0/24 allow
  log-queries: no
  log-replies: no
  log-local-actions: no
  do-ip4: yes
  do-ip6: no
  do-udp: yes
  do-tcp: yes
  hide-identity: yes
  hide-version: yes
EOF

systemctl enable unbound
systemctl restart unbound

# ── WireGuard wg0 設定 ────────────────────────────────────────────────────────
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

SERVER_PRIVATE_KEY="${SERVER_PRIVATE_KEY:?Set SERVER_PRIVATE_KEY}"

cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address    = 10.8.0.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIVATE_KEY}

# NAT (クライアントトラフィックを eth0 に出す)
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PreDown  = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Peers are managed dynamically by vpn-wg-agent
EOF

chmod 600 /etc/wireguard/wg0.conf

# IPv4 forwarding
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wg.conf
sysctl --system

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# ── vpn-wg-agent ─────────────────────────────────────────────────────────────
WG_AGENT_SECRET="${WG_AGENT_SECRET:?Set WG_AGENT_SECRET}"

pip3 install fastapi uvicorn pydantic

mkdir -p /opt/vpn-wg-agent
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "${SCRIPT_DIR}/main.py" /opt/vpn-wg-agent/main.py

cat > /etc/systemd/system/vpn-wg-agent.service << EOF
[Unit]
Description=vpn-wg-agent — WireGuard peer management API
After=network.target wg-quick@wg0.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vpn-wg-agent
Environment=WG_IFACE=wg0
Environment=WG_AGENT_PORT=8081
Environment=WG_AGENT_SECRET=${WG_AGENT_SECRET}
ExecStart=/usr/bin/python3 main.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vpn-wg-agent
systemctl start vpn-wg-agent

# ── ファイアウォール (ufw) ────────────────────────────────────────────────────
ufw allow 22/tcp     # SSH
ufw allow 51820/udp  # WireGuard
# 8081 (wg-agent) は localhost のみ — provisioner は CF Tunnel 経由でアクセス
ufw --force enable

echo ""
echo "=== インストール完了 ==="
SERVER_PUB_KEY=$(wg pubkey <<< "${SERVER_PRIVATE_KEY}")
echo "Server public key: ${SERVER_PUB_KEY}"
echo "-> この公開鍵を vertex_vpn_server.public_key に登録してください"
echo "-> VPS の公開 IP を vertex_vpn_server.public_ip に登録してください"
