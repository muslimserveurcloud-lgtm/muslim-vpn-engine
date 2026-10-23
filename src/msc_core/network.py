"""MSC Network Core — implémentation réseau native Python."""

import socket
import time


def resolve(host: str, port: int = 0) -> list[dict]:
    """Résout un nom d'hôte et retourne les adresses uniques."""
    results = []
    seen = set()

    for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        family, _, _, _, sockaddr = item
        address = sockaddr[0]
        key = (family, address)

        if key in seen:
            continue

        seen.add(key)
        results.append({
            "family": "IPv6" if family == socket.AF_INET6 else "IPv4",
            "address": address,
        })

    return results


def tcp_check(host: str, port: int, timeout: float = 5.0) -> dict:
    """Teste une connexion TCP sans envoyer de données applicatives."""
    started = time.monotonic()

    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = (time.monotonic() - started) * 1000
            return {
                "ok": True,
                "host": host,
                "port": port,
                "latency_ms": round(elapsed_ms, 2),
            }
    except OSError as exc:
        return {
            "ok": False,
            "host": host,
            "port": port,
            "error": str(exc),
        }


def udp_exchange(
    host: str,
    port: int,
    payload: bytes,
    timeout: float = 3.0,
) -> dict:
    """Envoie un datagramme UDP et attend une éventuelle réponse.

    L'absence de réponse ne signifie pas nécessairement que UDP est bloqué.
    """
    started = time.monotonic()

    try:
        addresses = socket.getaddrinfo(
            host, port, type=socket.SOCK_DGRAM
        )
        last_error = None

        for family, socktype, proto, _, sockaddr in addresses:
            try:
                with socket.socket(family, socktype, proto) as sock:
                    sock.settimeout(timeout)
                    sock.sendto(payload, sockaddr)

                    try:
                        data, peer = sock.recvfrom(65535)
                        return {
                            "sent": True,
                            "received": True,
                            "peer": str(peer),
                            "bytes_sent": len(payload),
                            "bytes_received": len(data),
                            "elapsed_ms": round(
                                (time.monotonic() - started) * 1000, 2
                            ),
                            "response_hex": data.hex(),
                        }
                    except socket.timeout:
                        return {
                            "sent": True,
                            "received": False,
                            "bytes_sent": len(payload),
                            "note": (
                                "Aucune réponse dans le délai ; "
                                "cela ne prouve pas un blocage UDP."
                            ),
                        }
            except OSError as exc:
                last_error = str(exc)

        return {"sent": False, "error": last_error or "Aucune adresse utilisable"}
    except OSError as exc:
        return {"sent": False, "error": str(exc)}
