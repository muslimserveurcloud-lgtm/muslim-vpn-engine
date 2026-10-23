#!/usr/bin/env python3
import argparse
import socket
import time
from datetime import datetime

def log(message):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)

def tcp_test(host, port, timeout):
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - started) * 1000
            log(f"TCP OK {host}:{port} - {elapsed:.1f} ms")
            return True
    except OSError as exc:
        log(f"TCP ECHEC {host}:{port} - {exc}")
        return False

def udp_test(host, port, timeout):
    # Envoie uniquement un petit datagramme de diagnostic.
    # Une absence de réponse ne prouve pas que le port est fermé.
    try:
        addresses = socket.getaddrinfo(
            host, port, type=socket.SOCK_DGRAM
        )
        family, socktype, proto, _, address = addresses[0]
        with socket.socket(family, socktype, proto) as sock:
            sock.settimeout(timeout)
            started = time.monotonic()
            sock.sendto(b"MSC-UDP-DIAG", address)
            try:
                data, peer = sock.recvfrom(2048)
                elapsed = (time.monotonic() - started) * 1000
                log(f"UDP REPONSE {peer} - {elapsed:.1f} ms - "
                    f"{len(data)} octets")
                return True
            except socket.timeout:
                log(f"UDP envoyé à {host}:{port}; aucune réponse "
                    "dans le délai. Résultat non concluant.")
                return False
    except OSError as exc:
        log(f"UDP ERREUR {host}:{port} - {exc}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="MUSLIM VPN ENGINE - diagnostic réseau"
    )
    parser.add_argument("mode", choices=("tcp", "udp", "dns"))
    parser.add_argument("host", help="Hôte à tester")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Le port doit être compris entre 1 et 65535.")
    if not 0.1 <= args.timeout <= 30:
        parser.error("Le délai doit être compris entre 0.1 et 30 secondes.")

    log(f"MUSLIM VPN ENGINE | mode={args.mode}")
    if args.mode == "tcp":
        ok = tcp_test(args.host, args.port, args.timeout)
        raise SystemExit(0 if ok else 1)
    elif args.mode == "udp":
        ok = udp_test(args.host, args.port, args.timeout)
        raise SystemExit(0 if ok else 1)
    else:
        try:
            for result in socket.getaddrinfo(args.host, None):
                log(f"DNS {result[4][0]}")
        except OSError as exc:
            log(f"DNS ECHEC - {exc}")
            raise SystemExit(1)

if __name__ == "__main__":
    main()
