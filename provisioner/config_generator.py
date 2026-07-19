# config_generator.py — builds WireGuard .conf file for the client
# Note: server private key is NEVER stored here; only server public key is used.
# Client private key is NEVER sent to the server — placeholder shown in comment only.

def generate_conf(
    assigned_ip: str,
    server_public_key: str,
    server_public_ip: str,
    server_listen_port: int,
    server_dns_ip: str,
) -> str:
    """
    Returns a ready-to-import WireGuard .conf string.
    The [Interface] PrivateKey line is left as a placeholder —
    the user fills in their own private key (generated locally).
    """
    return (
        "[Interface]\n"
        "# Paste your WireGuard private key here (generated on your device)\n"
        "PrivateKey = <YOUR_PRIVATE_KEY>\n"
        f"Address    = {assigned_ip}\n"
        f"DNS        = {server_dns_ip}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey           = {server_public_key}\n"
        f"Endpoint            = {server_public_ip}:{server_listen_port}\n"
        "AllowedIPs          = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )
