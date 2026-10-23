#!/usr/bin/env python3
import argparse
import select
import socket
import threading
import time

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connexion fermée pendant la négociation")
        data += chunk
    return data

def connect_proxy(proxy_host, proxy_port, target_host, target_port, timeout):
    proxy = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    proxy.settimeout(timeout)

    # SOCKS5 : version 5, une méthode proposée, aucune authentification.
    proxy.sendall(b"\x05\x01\x00")
    if recv_exact(proxy, 2) != b"\x05\x00":
        proxy.close()
        raise ConnectionError(
            "Le proxy ne prend pas en charge SOCKS5 sans authentification"
        )

    try:
        address = socket.inet_aton(target_host)
        atyp = b"\x01"
        encoded_host = address
    except OSError:
        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            proxy.close()
            raise ValueError("Nom d'hôte trop long")
        atyp = b"\x03"
        encoded_host = bytes([len(host_bytes)]) + host_bytes

    request = (
        b"\x05\x01\x00" + atyp + encoded_host
        + target_port.to_bytes(2, "big")
    )
    proxy.sendall(request)

    header = recv_exact(proxy, 4)
    if header[0] != 5 or header[1] != 0:
        proxy.close()
        raise ConnectionError(
            f"Connexion refusée par le proxy SOCKS5, code={header[1]}"
        )

    atyp_reply = header[3]
    if atyp_reply == 1:
        recv_exact(proxy, 4)
    elif atyp_reply == 4:
        recv_exact(proxy, 16)
    elif atyp_reply == 3:
        recv_exact(proxy, recv_exact(proxy, 1)[0])
    else:
        proxy.close()
        raise ConnectionError("Réponse SOCKS5 invalide")

    recv_exact(proxy, 2)  # Port de l'adresse de liaison.
    proxy.settimeout(None)
    return proxy

def relay(client, remote):
    sockets = [client, remote]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 300)
            if not readable:
                continue
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                destination = remote if source is client else client
                destination.sendall(data)
    except (OSError, ValueError):
        pass
    finally:
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

def main():
    parser = argparse.ArgumentParser(
        description="Relais TCP via un proxy SOCKS5 existant"
    )
    parser.add_argument("--proxy-host", required=True)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--listen-port", type=int, default=18080)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()

    if not 1 <= args.proxy_port <= 65535:
        parser.error("Port proxy invalide")
    if not 1 <= args.listen_port <= 65535:
        parser.error("Port local invalide")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.listen_port))
    listener.listen(32)

    print(
        f"[MSC] SOCKS5 relais local sur 127.0.0.1:{args.listen_port}",
        flush=True
    )
    print(
        "[MSC] Arrêt avec Ctrl+C. Proxy distant : "
        f"{args.proxy_host}:{args.proxy_port}",
        flush=True
    )

    try:
        while True:
            client, _ = listener.accept()
            threading.Thread(
                target=handle_client,
                args=(client, args),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[MSC] Arrêt demandé")
    finally:
        listener.close()

def handle_client(client, args):
    try:
        client.settimeout(args.timeout)
        # Le client local doit envoyer une requête HTTP CONNECT.
        request = b""
        while b"\r\n\r\n" not in request and len(request) < 16384:
            chunk = client.recv(4096)
            if not chunk:
                return
            request += chunk

        first = request.split(b"\r\n", 1)[0].decode("latin-1")
        parts = first.split()
        if len(parts) != 3 or parts[0].upper() != "CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return

        host, separator, port_text = parts[1].rpartition(":")
        if not separator or not host:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError("Port cible invalide")

        remote = connect_proxy(
            args.proxy_host, args.proxy_port, host, port, args.timeout
        )
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        client.settimeout(None)

        print(f"[MSC] Tunnel TCP établi vers {host}:{port}", flush=True)

        # Conserver les éventuelles données reçues après les en-têtes HTTP.
        header_end = request.find(b"\r\n\r\n") + 4
        remaining = request[header_end:]
        if remaining:
            remote.sendall(remaining)

        relay(client, remote)
    except Exception as exc:
        print(f"[MSC] Connexion échouée : {exc}", flush=True)
        try:
            client.close()
        except OSError:
            pass

if __name__ == "__main__":
    main()
