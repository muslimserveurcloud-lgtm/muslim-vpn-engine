"""Importateur local de configurations V2Ray pour MUSLIM VPN ENGINE."""

import base64
import json
from urllib.parse import urlsplit, parse_qs, unquote


SUPPORTED_SCHEMES = {
    "vless", "vmess", "trojan", "ss",
    "socks", "socks5", "http", "https",
}


def decode_base64_text(value):
    value = value.strip()
    value += "=" * (-len(value) % 4)

    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(value).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            pass

    raise ValueError("Base64 invalide ou texte non UTF-8")


def import_vmess(link):
    encoded = link[len("vmess://"):].strip()
    raw = decode_base64_text(encoded)
    data = json.loads(raw)

    if not isinstance(data, dict):
        raise ValueError("La configuration VMess doit être un objet JSON")

    host = data.get("add")
    port = data.get("port")
    user_id = data.get("id")

    if not host or not port or not user_id:
        raise ValueError("VMess doit contenir add, port et id")

    return {
        "format": "share-link",
        "protocol": "vmess",
        "name": data.get("ps") or "VMess",
        "server": str(host),
        "port": int(port),
        "uuid": str(user_id),
        "transport": data.get("net", "tcp"),
        "tls": str(data.get("tls", "")).lower() in ("tls", "true", "1"),
        "source_fields": data,
        "status": "parsed-not-connected",
    }


def import_uri(link):
    link = link.strip()

    if link.lower().startswith("vmess://"):
        return import_vmess(link)

    parsed = urlsplit(link)
    scheme = parsed.scheme.lower()

    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(f"Format non pris en charge : {scheme or 'inconnu'}")

    query = parse_qs(parsed.query, keep_blank_values=True)
    host = parsed.hostname
    port = parsed.port

    if scheme in ("vless", "trojan", "ss") and (not host or not port):
        raise ValueError("Le lien doit contenir un serveur et un port")

    protocol = {"socks5": "socks"}.get(scheme, scheme)
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    if scheme == "ss" and not password and username:
        # Ancien format Shadowsocks entièrement encodé en Base64.
        try:
            decoded = decode_base64_text(
                link[len("ss://"):].split("#", 1)[0]
            )
            method, credentials = decoded.split(":", 1)
            password, hostport = credentials.rsplit("@", 1)
            host, port_text = hostport.rsplit(":", 1)
            port = int(port_text)
            username = method
        except (ValueError, TypeError):
            raise ValueError("Format Shadowsocks non reconnu")

    return {
        "format": "share-link",
        "protocol": protocol,
        "name": unquote(parsed.fragment) or protocol.upper(),
        "server": host,
        "port": port,
        "username": username,
        "password": password,
        "uuid": username if protocol == "vless" else None,
        "transport": query.get("type", ["tcp"])[0],
        "security": query.get("security", ["none"])[0],
        "sni": query.get("sni", query.get("peer", [""]))[0],
        "path": query.get("path", [""])[0],
        "host_header": query.get("host", [""])[0],
        "flow": query.get("flow", [""])[0],
        "status": "parsed-not-connected",
    }


def import_config(text):
    text = text.strip()

    if text.startswith("{"):
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("La configuration JSON doit être un objet")

        if not any(key in data for key in ("outbounds", "inbounds")):
            raise ValueError("JSON valide, mais structure V2Ray non reconnue")

        return {
            "format": "v2ray-json",
            "protocol": "custom-json",
            "status": "parsed-not-connected",
            "config": data,
        }

    if "://" in text:
        return import_uri(text)

    # Une subscription Base64 peut contenir plusieurs liens.
    try:
        decoded = decode_base64_text(text)
        if "://" in decoded:
            links = [
                line.strip()
                for line in decoded.splitlines()
                if "://" in line
            ]
            return {
                "format": "subscription-text",
                "nodes": [import_uri(line) for line in links],
                "status": "parsed-not-connected",
            }
    except (ValueError, UnicodeDecodeError):
        pass

    raise ValueError("Ni lien reconnu, ni JSON V2Ray, ni abonnement reconnu")


def main():
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Importateur V2Ray local — MUSLIM VPN ENGINE"
    )
    parser.add_argument("file", help="Fichier de configuration ou de liens")
    parser.add_argument(
        "--output",
        help="Fichier JSON de sortie (facultatif)",
    )
    args = parser.parse_args()

    result = import_config(Path(args.file).read_text(encoding="utf-8"))
    rendered = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"Configuration importée dans : {args.output}")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
