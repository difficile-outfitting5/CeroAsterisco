#!/usr/bin/env python3
"""get_ca.py — Fase 2: adquirir y verificar la CA raiz del interceptor TLS Fortinet.

READ-ONLY: no importa certs, no toca llaveros, solo escribe en --outdir.
100% stdlib Python 3.10+. Sin root. Solo sockets TCP connect().
"""

import argparse
import binascii
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

# =============================================================================
# 1. CONSTANTES (rutas candidatas, OIDs, vectores)
# =============================================================================

TOOL_NAME = "get_ca"
TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0"

DEFAULT_REPORT = "fgt_profile.json"
OUT_PEM = "fortinet_ca.pem"
OUT_JSON = "get_ca.json"

# AKI observado en la Fase 1 (pin de referencia del usuario).
EXPECTED_AKI_DEFAULT = ("6E:57:23:CE:F2:9C:43:FA:63:C4:01:CA:"
                        "67:AA:30:E8:ED:7E:32:48")

# OID extensiones X.509 que nos importan.
OID_SKI = "2.5.29.14"
OID_KEY_USAGE = "2.5.29.15"
OID_AKI = "2.5.29.35"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_SAN = "2.5.29.17"

# Nombres de dominio SNI con los que pedir certificados al interceptor.
# Un FortiGate en inspeccion profunda re-firma cualquier host; usar varios
# aumenta la probabilidad de ver la misma CA en >=2 cadenas (check blando).
REFRESH_SNIS = ("instagram.com", "www.google.com", "update.code.visualstudio.com")

TLS_PORTS = (443, 8443, 10443)
HTTP_PORT_PRIORITY = (443, 8443, 10443, 80, 8008)

# Rutas del portal que pueden enlazar o servir el cert de la CA local.
CERT_PATHS = ("/remote/cert", "/api/v2/cmdb/system/ca.cert",
              "/login/certificate", "/remote/cert/fortinet")
CERT_LINK_RE = re.compile(r'href=["\']([^"\']*(?:\.cer|\.crt|\.pem|\.der|cert)[^"\']*)["\']',
                          re.IGNORECASE)

# Cabeceras de contenido que indican DER/x509 descargable.
CERT_CT_RE = re.compile(r"application/(x-x509|pkix-cert|octet-stream)", re.I)

KEY_ALG_NAMES = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10045.3.1.7": "EC-P256",
    "1.3.101.112": "Ed25519",
    "1.3.101.110": "X25519",
}

SIG_OID_HASH = {
    "1.2.840.113549.1.1.5": "md5", "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.10045.4.3.2": "ecdsa-sha256", "1.2.840.10045.4.3.3": "ecdsa-sha384",
    "1.2.840.10045.4.3.4": "ecdsa-sha512",
    "1.2.840.113549.1.1.4": "md5-rsa", "1.2.840.113549.1.1.3": "sha1-rsa",
    "1.3.101.112": "ed25519",
}

ATTR_SHORT = {"CN": "CN", "OU": "OU", "O": "O", "C": "C", "ST": "ST",
              "L": "L", "DC": "DC", "E": "EMAIL"}
ATTR_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "TITLE", "2.5.4.42": "CN",
    "0.9.2342.19200300.100.1.25": "DC", "1.2.840.113549.1.9.1": "EMAIL",
    "2.5.4.5": "SERIALNUMBER",
}

VERBOSE = False


def log(msg):
    if VERBOSE:
        print(f"[{TOOL_NAME}] {msg}", file=sys.stderr)


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


# =============================================================================
# 2. UTILIDADES PURAS (PEM/DER, hashing, nombres)
# =============================================================================

def hexnorm(v):
    """Normaliza un identificador hex a MAYUSCULAS SIN separadores."""
    if not v:
        return None
    return re.sub(r"[:\s<>]", "", str(v)).upper() or None


def pretty_hex(h):
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2)) if h else None


def pem_from_der(der):
    b = binascii.b2a_base64(der, newline=False).decode("ascii")
    body = "\n".join(b[i:i + 64] for i in range(0, len(b), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def der_from_pem(text):
    """Extrae todos los bloques PEM de certificado y los devuelve en DER."""
    out = []
    for m in re.finditer(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
                         text, re.S):
        raw = re.sub(r"\s+", "", m.group(1))
        try:
            out.append(binascii.a2b_base64(raw))
        except binascii.Error:
            continue
    return out


def name_to_str(name):
    """DN dict {'CN':..,'O':..} -> cadena canonica ordenada para comparar."""
    if not isinstance(name, dict):
        return ""
    order = ("C", "ST", "L", "O", "OU", "CN", "DC", "EMAIL", "SERIALNUMBER", "TITLE")
    parts = [f"{k}={name[k]}" for k in order if name.get(k)]
    parts += [f"{k}={v}" for k, v in sorted(name.items()) if k not in order and v]
    return ",".join(parts).upper()


def attr(name, key):
    return (name or {}).get(key)


# =============================================================================
# 3. PARSER X.509 MINIMO (ASN.1/DER a mano)
# =============================================================================
# Objetivo: LEER certificados, no firmarlos. Cubre lo que necesita la
# verificacion (subject/issuer/AKI/SKI/BC/fechas/clave) y nada mas.

class DerError(ValueError):
    pass


def _read_tlv(buf, pos):
    """Devuelve (tag, payload_bytes, nueva_posicion)."""
    if pos >= len(buf):
        raise DerError("TLV fuera de rango")
    tag = buf[pos]
    pos += 1
    if pos >= len(buf):
        raise DerError("longitud ausente")
    first = buf[pos]
    pos += 1
    if first < 0x80:
        ln = first
    elif first == 0x80:
        raise DerError("modo indefinido no soportado")
    else:
        nbytes = first & 0x7F
        if nbytes > 4 or pos + nbytes > len(buf):
            raise DerError("longitud inválida")
        ln = int.from_bytes(buf[pos:pos + nbytes], "big")
        pos += nbytes
    if pos + ln > len(buf):
        raise DerError("payload truncado")
    return tag, buf[pos:pos + ln], pos + ln


def children(buf):
    """Itera los TLV hijos de un contenedor ya desencapsulado."""
    pos, out = 0, []
    while pos < len(buf):
        tag, val, pos = _read_tlv(buf, pos)
        out.append((tag, val))
    return out


def oid_str(enc):
    """Decodifica un OID DER (sin cabecera TLV) a formato punteado."""
    if not enc:
        return ""
    nums = [enc[0] // 40, enc[0] % 40]
    val = 0
    for b in enc[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            nums.append(val)
            val = 0
    return ".".join(map(str, nums))


def parse_time(enc):
    s = enc.decode("ascii", "replace").strip()
    try:
        if len(s) == 13 and s[-1] == "Z":       # UTCTime YYMMDDHHMMSSZ
            yy = int(s[0:2])
            yy += 2000 if yy < 50 else 1900
            return datetime(yy, int(s[2:4]), int(s[4:6]), int(s[6:8]),
                            int(s[8:10]), int(s[10:12]), tzinfo=timezone.utc)
        if len(s) == 15 and s[-1] == "Z":       # GeneralizedTime YYYYMMDD...
            return datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]),
                            int(s[10:12]), int(s[12:14]), tzinfo=timezone.utc)
    except ValueError:
        return None
    return None


def decode_string(tag, val):
    if tag in (0x0C, 0x16, 0x1E):               # UTF8, Printable, BMP
        return val.decode("utf-8", "replace")
    if tag in (0x13, 0x14):                    # Printable / T61
        return val.decode("latin-1", "replace")
    return val.hex()


def parse_name(enc):
    """RDNSequence -> dict {ATTR: valor}. Si hay repetidos se conservan en lista."""
    name = {}
    for _, rdn in children(enc):
        for _, atv in children(rdn):
            items = children(atv)
            if len(items) < 2:
                continue
            oid = oid_str(items[0][1])
            key = ATTR_NAMES.get(oid, oid)
            key = ATTR_SHORT.get(key, key)
            val = decode_string(items[1][0], items[1][1])
            if key in name:
                prev = name[key]
                name[key] = prev if isinstance(prev, list) else [prev, val]
            else:
                name[key] = val
    return name


def parse_extensions(ext_block):
    exts = {}
    for _, exts_seq in children(ext_block):            # Extensions ::= SEQUENCE
        for _, e in children(exts_seq):                # cada Extension
            items = children(e)
            if len(items) < 2:
                continue
            oid = oid_str(items[0][1])
            # Extension ::= SEQUENCE { OID, critical BOOLEAN DEFAULT FALSE,
            #   extnValue OCTET STRING }. El payload del OID va SIEMPRE envuelto
            #   en OCTET STRING (tag 0x04); desencapsularlo una vez. Buscar el
            #   0x04 por etiqueta y no por indice: con critical=TRUE el ultimo
            #   item sigue siendo el OCTET STRING pero el penultimo es BOOLEAN.
            payload = None
            for t, v in items:
                if t == 0x04:
                    payload = children(v)[0][1]        # desenvuelve extnValue
                    break
            if payload is None:
                continue
            try:
                if oid == OID_SKI:
                    exts["ski"] = payload.hex().upper()
                elif oid == OID_AKI:
                    for tag, val in children(payload):  # keyIdentifier [0]/[1]
                        if tag in (0x80, 0x81, 0x86):
                            exts["aki"] = val.hex().upper()
                            break
                elif oid == OID_BASIC_CONSTRAINTS:
                    c = children(payload)
                    # SEQUENCE vacio == CA:FALSE implicito
                    exts["ca"] = bool(c) and c[0][0] == 0x01 and c[0][1] != b"\x00"
                elif oid == OID_KEY_USAGE:
                    first = payload[1] if len(payload) > 1 else 0  # BIT STRING
                    ku = []
                    if first & 0x20:
                        ku.append("keyCertSign")
                    if first & 0x40:
                        ku.append("cRLSign")
                    if first & 0x80:
                        ku.append("digitalSignature")
                    exts["key_usage"] = ku
                elif oid == OID_SAN:
                    for _, g in children(payload):
                        if g[0] == 0x82:               # dNSName [2]
                            exts.setdefault("san", []).append(
                                g[1].decode("ascii", "replace"))
            except (DerError, IndexError):
                continue
    return exts


def parse_cert(der):
    """DER -> dict plano con todo lo que usa el verificador.

    Secuencia TBS (RFC 5280): [version], serial, sigAlg, issuer, validity,
    subject, SPKI, [[extensions]]. Los campos opcionales obligan a avanzar
    por etiqueta en vez de por indice fijo.
    """
    cert = children(der)[0][1]
    outer = children(cert)
    tbs = outer[0][1]
    els = children(tbs)
    pos = 0
    version = 1
    if els[pos][0] == 0xA0:
        v = children(els[pos][1])
        version = (v[0][1][0] if v else 0) + 1
        pos += 1
    serial = els[pos][1].hex().lstrip("0").upper() or "0"
    pos += 1
    sig_alg_oid = oid_str(children(els[pos][1])[0][1])
    pos += 1
    issuer = parse_name(els[pos][1]); pos += 1
    times = children(els[pos][1])
    nb, na = parse_time(times[0][1]), parse_time(times[1][1]); pos += 1
    subject = parse_name(els[pos][1]); pos += 1
    spki_items = children(els[pos][1])
    key_oid = oid_str(children(spki_items[0][1])[0][1])
    pub_bits = spki_items[1][1][1:]                 # BIT STRING sin byte inicial
    pos += 1

    info = {"version": version, "serial": serial, "issuer": issuer,
            "subject": subject, "not_before": nb, "not_after": na,
            "sig_alg": SIG_OID_HASH.get(sig_alg_oid, sig_alg_oid),
            "key_oid": key_oid,
            "key_alg": KEY_ALG_NAMES.get(key_oid, key_oid),
            "pub_der": pub_bits, "ski": None, "aki": None,
            "ca": False, "key_usage": [], "san": []}

    for tag, val in els[pos:]:
        if tag == 0xA3:                             # extensions
            info.update(parse_extensions(val))
    info["self_signed"] = name_to_str(subject) == name_to_str(issuer)
    return info


# =============================================================================
# 4. CAPA DE RED (TLS sin verificacion, captura de cadena)
# =============================================================================

def make_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # queremos el cert roto, no el error
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def capture_chain(ip, port, sni, timeout):
    """Cadena TLS completa (DER) vista desde el peer, hoja primero.

    Fuente 1: handshake raw propio (stdlib socket puro, sin verificacion) ->
    lista DER real del mensaje Certificate. Fuente 2 (fallback): ssl stdlib,
    que solo expone la hoja pero confirma conectividad/cifra.
    """
    ders = raw_tls_chain(ip, port, sni, timeout)
    if ders:
        return ders
    ctx = make_ctx()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                leaf = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        log(f"tls {ip}:{port} sni={sni}: {exc}")
        return []
    return [leaf] if leaf else []


def raw_tls_chain(ip, port, sni, timeout):
    """Handshake TLS1.2 a bajo nivel (socket stdlib puro) para volcar la cadena.

    ssl stdlib solo expone la hoja via getpeercert(); los demas certs del
    mensaje Certificate van dentro de los records TLS. Parseamos records y
    reensamblamos handshake messages sin verificar nada ni completar el
    handshake (cerramos tras ServerHelloDone). Devuelve lista DER o [].
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.sendall(client_hello(sni))
            recs, buf, hs = [], b"", None
            while True:
                chunk = raw.recv(65536)
                if not chunk:
                    break
                buf += chunk
                recs, buf = drain_records(buf)
                for t, p in recs:
                    if t == 0x15 and p and p[0] == 0x02:     # alert fatal
                        raise OSError(f"alert TLS desc={p[1]}")
                hs = handshake_messages(recs)
                if hs is not None:
                    break
                if len(buf) > 4_000_000:                     # defensa anti-desborde
                    break
            return certificates_from_hs(hs or {})
    except (OSError, ssl.SSLError, DerError, IndexError) as exc:
        log(f"raw tls {ip}:{port} sni={sni}: {exc}")
        return []


def client_hello(sni):
    """ClientHello TLS1.2 minimo con SNI, support_groups y signature_algorithms.

    Sin support_groups el server descarta las suites ECDHE; sin anunciar
    rsa+sha256 (0x0401) rechaza certs RSA firmados con SHA-256. Orden de
    campos segun RFC 5246.
    """
    host = sni.encode("ascii")
    entry = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_data = len(entry).to_bytes(2, "big") + entry
    sni_ext = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
    groups = bytes.fromhex("001d001700180019")     # x25519, secp256/384/521r1
    groups_ext = (b"\x00\x0a" + (2 + len(groups)).to_bytes(2, "big") +
                  len(groups).to_bytes(2, "big") + groups)
    sig_list = bytes.fromhex("0401050106010203040305030603020103010101")
    sig_algs = len(sig_list).to_bytes(2, "big") + sig_list
    sig_ext = b"\x00\x0d" + len(sig_algs).to_bytes(2, "big") + sig_algs
    exts = sni_ext + groups_ext + sig_ext
    suites = bytes.fromhex(
        "c030c02cc02fc02bc02ec027c028c024c023cca9cca8c00ac01400a300a2"
        "009d009c003d003c0035002f000a001300ff")
    body = (b"\x03\x03" + os.urandom(32) +
            b"\x00" +                                   # session id: vacio
            len(suites).to_bytes(2, "big") + suites +
            b"\x01\x00" +                               # compression: null
            len(exts).to_bytes(2, "big") + exts)
    hello = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hello).to_bytes(2, "big") + hello


def drain_records(buf):
    """Separa records TLS completos; devuelve (lista_payloads, resto)."""
    out = []
    while len(buf) >= 5:
        typ, major, minor = buf[0], buf[1], buf[2]
        ln = int.from_bytes(buf[3:5], "big")
        if len(buf) < 5 + ln:
            break
        out.append((typ, buf[5:5 + ln]))
        buf = buf[5 + ln:]
    return out, buf


def handshake_messages(recs):
    """Reensambla mensajes de handshake; devuelve dict cuando ya hay Certificate."""
    stream = b"".join(p for t, p in recs if t == 0x16)
    msgs, pos, have_done = {}, 0, False
    while pos + 4 <= len(stream):
        mtype = stream[pos]
        mlen = int.from_bytes(stream[pos + 1:pos + 4], "big")
        if pos + 4 + mlen > len(stream):
            break                       # mensaje incompleto: esperar mas records
        body = stream[pos + 4:pos + 4 + mlen]
        pos += 4 + mlen
        if mtype == 0x02:
            msgs["server_hello"] = body
        elif mtype == 0x0b:
            msgs["certificate"] = body
        elif mtype == 0x0e:
            have_done = True
        if have_done and "certificate" in msgs:
            return msgs
    return msgs if ("certificate" in msgs and have_done) else None


def certificates_from_hs(msgs):
    """TLS Certificate message -> lista de DER."""
    body = msgs.get("certificate")
    if not body:
        return []
    total = int.from_bytes(body[0:3], "big")
    certs, pos = [], 3
    while pos + 3 <= 3 + total:
        clen = int.from_bytes(body[pos:pos + 3], "big")
        pos += 3
        der = body[pos:pos + clen]
        pos += clen
        if der:
            certs.append(der)
    return certs


def _which(prog):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        c = os.path.join(d, prog)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def http_get(ip, port, path, timeout, use_tls):
    """GET minimo; devuelve (status, headers_dict, body_bytes) o None."""
    try:
        if use_tls:
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout,
                                               context=make_ctx())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", path, headers={"Host": ip, "User-Agent": TOOL_NAME})
        resp = conn.getresponse()
        body = resp.read(200_000)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        conn.close()
        return status, headers, body
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        log(f"http {ip}:{port}{path}: {exc}")
        return None


# =============================================================================
# 5. VECTORES DE ADQUISICION
# =============================================================================

def vec_tls_chain(target_ip, ports, snis, timeout, attempts_log):
    """Vector 1: cadenas TLS desde puertos TLS del interceptor, con 2+ SNI."""
    found = []
    ports_alive = set()
    for port in ports:
        for sni in snis:
            ders = capture_chain(target_ip, port, sni, timeout)
            if not ders:
                continue
            ports_alive.add(port)
            for d in ders:
                found.append({"der": d, "vector": "tls_chain",
                              "detail": f"{target_ip}:{port} sni={sni}"})
            break  # un SNI basta por puerto; los demas puertos dan las cadenas extra
    if found:
        attempts_log.append({"vector": "tls_chain", "result": "hit",
                             "detail": f"{len(found)} certs desde puerto(s) "
                                       f"{sorted(ports_alive)}"})
    else:
        attempts_log.append({"vector": "tls_chain", "result": "miss",
                             "detail": "handshake TLS sin resultado en "
                                       f"puertos {list(ports)}"})
    return found


def vec_keychain(attempts_log):
    """Vector 2: llavero macOS (security find-certificate). Read-only."""
    sec = _which("security")
    if not sec or sys.platform != "darwin":
        attempts_log.append({"vector": "keychain", "result": "miss",
                             "detail": "solo aplica en macOS"})
        return []
    try:
        p = subprocess.run([sec, "find-certificate", "-a", "-c", "Fortinet", "-p"],
                           capture_output=True, timeout=10)
        text = p.stdout.decode("ascii", "replace")
        ders = der_from_pem(text)
        if ders:
            attempts_log.append({"vector": "keychain", "result": "hit",
                                 "detail": f"{len(ders)} certs en llavero"})
            return [{"der": d, "vector": "keychain", "detail": "macOS security"}
                    for d in ders]
    except (subprocess.SubprocessError, OSError) as exc:
        attempts_log.append({"vector": "keychain", "result": "error",
                             "detail": str(exc)})
        return []
    attempts_log.append({"vector": "keychain", "result": "miss",
                         "detail": "sin certs 'Fortinet' en llavero"})
    return []


def vec_portal_html(target_ip, ports, timeout, attempts_log):
    """Vectores 3+4: parsear portal y rutas directas de descarga de cert."""
    hits = []
    tried_any = False
    for port in ports:
        for path in ("/", "/remote/login", "/login"):
            r = http_get(target_ip, port, path, timeout,
                         port not in (80, 8008))
            if not r:
                continue
            tried_any = True
            status, headers, body = r
            links = set(CERT_LINK_RE.findall(body.decode("latin-1", "replace")))
            for link in list(links)[:5]:
                u = urlsplit(link if link.startswith("/") else "/" + link)
                rr = http_get(target_ip, port, u.path + (("?" + u.query) if u.query else ""),
                              timeout, port not in (80, 8008))
                if not rr:
                    continue
                st2, hd2, bd2 = rr
                ctype = hd2.get("content-type", "")
                ders = der_from_pem(bd2.decode("latin-1", "replace"))
                if not ders and (CERT_CT_RE.search(ctype) or bd2[:1] == b"\x30"):
                    try:
                        children(bd2)          # valida que sea DER plausible
                        ders = [bd2]
                    except DerError:
                        ders = []
                for d in ders:
                    hits.append({"der": d, "vector": "portal_html",
                                 "detail": f"{path}->{link}"})
            break  # primera ruta que responde basta por puerto
    for port in ports:
        for path in CERT_PATHS:
            r = http_get(target_ip, port, path, timeout, port not in (80, 8008))
            if not r:
                continue
            tried_any = True
            status, headers, body = r
            ders = der_from_pem(body.decode("latin-1", "replace"))
            if not ders and body[:1] == b"\x30":
                try:
                    children(body)
                    ders = [body]
                except DerError:
                    ders = []
            for d in ders:
                hits.append({"der": d, "vector": "direct_path",
                             "detail": f":{port}{path} status={status}"})
    if hits:
        attempts_log.append({"vector": "portal_html/direct", "result": "hit",
                             "detail": f"{len(hits)} candidatos"})
    else:
        attempts_log.append({"vector": "portal_html/direct",
                             "result": "miss" if tried_any else "error",
                             "detail": "portal sin enlaces/rutas de cert"})
    return hits


def vec_local_stores(attempts_log):
    """Vector 5: almacenes locales (NSS db dir, /etc/ssl/certs, user keychain dir)."""
    hits = []
    candidates_dirs = []
    home = os.path.expanduser("~")
    nss = os.path.join(home, ".pki", "nssdb")
    if os.path.isdir(nss):
        candidates_dirs.append(nss)
    if sys.platform == "darwin":
        cand = os.path.join(home, "Library", "Keychains")
        if os.path.isdir(cand):
            candidates_dirs.append(cand)
    else:
        for d in ("/etc/ssl/certs", "/usr/local/share/ca-certificates"):
            if os.path.isdir(d):
                candidates_dirs.append(d)
    seen = set()
    for d in candidates_dirs:
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            continue
        for fn in entries:
            low = fn.lower()
            if not low.endswith((".pem", ".crt", ".cer", ".der")):
                continue
            full = os.path.join(d, fn)
            if "fortinet" not in low and "fortigate" not in low:
                continue
            try:
                data = open(full, "rb").read(300_000)
            except OSError:
                continue
            ders = der_from_pem(data.decode("latin-1", "replace")) \
                if b"BEGIN CERTIFICATE" in data else ([data] if data[:1] == b"\x30" else [])
            for der in ders:
                sh = hashlib.sha256(der).hexdigest()
                if sh in seen:
                    continue
                seen.add(sh)
                hits.append({"der": der, "vector": "local_store", "detail": full})
    attempts_log.append({"vector": "local_store",
                         "result": "hit" if hits else "miss",
                         "detail": f"{len(hits)} certs Fortinet en almacenes"})
    return hits


def vec_admin_gui(target_ip, ports, creds, timeout, attempts_log):
    """Vector 6: GUI admin con credenciales (si las hay). Download Local CA."""
    if not creds or not creds[0]:
        attempts_log.append({"vector": "admin_gui", "result": "miss",
                             "detail": "sin credenciales"})
        return []
    user, pw = creds
    hits = []
    for port in ports:
        use_tls = port not in (80, 8008)
        # login form POST (mfd_login) y despues descarga de la CA local
        login_body = ("username=%s&credential=%s&forward=%2F&ajax=1"
                      % (quote(user), quote(pw)))
        try:
            conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
            conn = conn_cls(target_ip, port, timeout=timeout,
                            context=make_ctx() if use_tls else None)
            conn.request("POST", "/logincheck", body=login_body,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp = conn.getresponse()
            cookie = resp.getheader("Set-Cookie") or ""
            resp.read()
            conn.close()
            if not cookie:
                continue
            for path in ("/api/v2/cmdb/system/certificate?filter=name eq 'Fortinet'&fields=*",
                         "/system/cert?name=Fortinet_CA_SSL"):
                try:
                    conn = conn_cls(target_ip, port, timeout=timeout,
                                   context=make_ctx() if use_tls else None)
                    conn.request("GET", path, headers={"Cookie": cookie.split(";")[0]})
                    r = conn.getresponse()
                    body = r.read(300_000)
                    conn.close()
                except (OSError, http.client.HTTPException):
                    continue
                ders = der_from_pem(body.decode("latin-1", "replace"))
                for d in ders:
                    hits.append({"der": d, "vector": "admin_gui",
                                 "detail": f":{port}{path}"})
        except (OSError, http.client.HTTPException, ssl.SSLError):
            continue
        if hits:
            break
    attempts_log.append({"vector": "admin_gui",
                         "result": "hit" if hits else "miss",
                         "detail": f"{len(hits)} certs via GUI"})
    return hits




# =============================================================================
# 7. VERIFICADOR
# =============================================================================

def rsa_pub_from_der(bits):
    """RSAPublicKey DER -> (n, e)."""
    items = children(bits)
    n = int.from_bytes(items[0][1], "big")
    e = int.from_bytes(items[1][1], "big")
    return n, e


def pkcs1_v15_check(em, msg_hash_oid, digest_name):
    """Comprueba el padding PKCS#1 v1.5 y extrae el DigestInfo."""
    if em[0] != 0 or em[1] != 1:
        return False
    sep = em.find(b"\x00", 2)
    if sep < 10:
        return False
    di = em[sep + 1:]
    try:
        items = children(di)
        got_oid = oid_str(children(items[0][1])[0][1])
    except (DerError, IndexError):
        return False
    want = {v: k for k, v in SIG_OID_HASH.items()}.get(digest_name)
    return got_oid == want if want else True


def verify_leaf_signature(ca, leaf):
    """Firma RSA-PKCS1v1.5 de la hoja verificada con la clave de la CA.

    Devuelve True/False/None(no_verificado).
    """
    if not ca.get("pub_der") or not leaf:
        return None
    if ca.get("key_alg") != "RSA":
        return None
    try:
        n, e = rsa_pub_from_der(ca["pub_der"])
        cert_items = children(leaf["raw_der"])
        outer = children(cert_items[0][1])
        sig_alg_enc = outer[1][1]
        sig_bits = outer[2][1][1:]
        tbs = outer[0][1]
    except (DerError, IndexError):
        return None
    alg_oid = oid_str(children(sig_alg_enc)[0][1])
    digest = SIG_OID_HASH.get(alg_oid)
    if digest is None or not digest.endswith(("sha256", "sha1", "sha512", "sha384")):
        return None
    hname = digest.split("-")[-1]
    sig = int.from_bytes(sig_bits, "big")
    em = pow(sig, e, n).to_bytes((n.bit_length() + 7) // 8, "big")
    want = hashlib.new(hname, tbs).digest()
    # DigestInfo debe contener el hash exacto tras el AlgorithmIdentifier
    if want not in em:
        return False
    return pkcs1_v15_check(em, alg_oid, hname)


def verify_candidate(ca_info, leaf_info, expected_aki, now=None):
    """Checks duros + blandos -> dict verification + confidence."""
    now = now or datetime.now(timezone.utc)
    res = {}
    res["subject_issuer_match"] = bool(leaf_info) and \
        name_to_str(ca_info["subject"]) == name_to_str(leaf_info["issuer"])
    # aki_ski_match: si la hoja no lleva AKI (emitentes minimos, ej. CA
    # autogenerada sin -copy_extensions), el emparejado se sustituye por el
    # pin expected_aki vs SKI de la CA. Nunca se acepta con AKI en desacuerdo.
    if leaf_info and leaf_info.get("aki") and ca_info.get("ski"):
        res["aki_ski_match"] = hexnorm(leaf_info["aki"]) == hexnorm(ca_info["ski"])
    elif expected_aki and ca_info.get("ski"):
        res["aki_ski_match"] = hexnorm(expected_aki) == hexnorm(ca_info["ski"])
    else:
        res["aki_ski_match"] = False
    res["ca_true"] = bool(ca_info.get("ca"))
    res["self_signed"] = bool(ca_info.get("self_signed"))
    res["valid_dates"] = bool(ca_info.get("not_before") and ca_info.get("not_after")
                              and ca_info["not_before"] <= now <= ca_info["not_after"])
    hard = ["subject_issuer_match", "ca_true", "self_signed", "valid_dates"]
    hard_ok = all(res[h] for h in hard) and res["aki_ski_match"]
    res["expected_aki_match"] = bool(expected_aki) and ca_info.get("ski") and \
        hexnorm(ca_info["ski"]) == hexnorm(expected_aki)
    conf = 0.0
    if res["subject_issuer_match"]:
        conf += 0.25
    if res["aki_ski_match"]:
        conf += 0.25
    if res["ca_true"]:
        conf += 0.15
    if res["self_signed"]:
        conf += 0.15
    if res["valid_dates"]:
        conf += 0.10
    if res["expected_aki_match"]:
        conf += 0.10
    return res, hard_ok, min(conf, 1.0)


# =============================================================================
# 8. RANKING Y SELECCION
# =============================================================================

VECTOR_PRIORITY = {"tls_chain": 0, "keychain": 1, "portal_html": 2,
                   "direct_path": 2, "local_store": 3, "admin_gui": 4}


def dedupe_and_rank(cands):
    by_sha = {}
    for c in cands:
        sh = c["sha256"]
        if sh not in by_sha:
            by_sha[sh] = c
            c["chains"] = {c["detail"]}
            c["vectors"] = {c["vector"]}
        else:
            by_sha[sh]["chains"].add(c["detail"])
            by_sha[sh]["vectors"].add(c["vector"])
    for c in by_sha.values():
        c["seen_in"] = len(c["chains"])
    ranked = sorted(by_sha.values(),
                    key=lambda c: (-c["verification"]["confidence"],
                                   min(VECTOR_PRIORITY.get(v, 9) for v in c["vectors"]),
                                   c["sha256"]))
    return ranked


# =============================================================================
# 9. SALIDA (PEM + JSON + handoff)
# =============================================================================

def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def candidate_json(c):
    return {
        "subject": c["info"]["subject"], "issuer": c["info"]["issuer"],
        "serial": c["info"]["serial"], "aki": pretty_hex(c["info"].get("aki")),
        "ski": pretty_hex(c["info"].get("ski")), "sha256": c["sha256"],
        "not_before": iso(c["info"]["not_before"]),
        "not_after": iso(c["info"]["not_after"]),
        "key_algo": c["info"]["key_alg"],
        "is_ca": c["info"]["ca"], "self_signed": c["info"]["self_signed"],
        "source_vector": c["vector"], "detail": c["detail"],
        "verification": c["verification"],
    }


def write_outputs(outdir, report, selected, all_cands, vectors_tried, notes):
    os.makedirs(outdir, exist_ok=True)
    pem_path = os.path.join(outdir, OUT_PEM)
    json_path = os.path.join(outdir, OUT_JSON)
    if selected:
        with open(pem_path, "w", encoding="ascii") as f:
            f.write(pem_from_der(selected["der"]))
    ser = (report.get("serial")
             or (attr(selected["info"]["subject"], "OU") if selected else None))
    # El OU del issuer es el serial del dispositivo; si el informe no traia
    # modelo, se deriva del prefijo del serial (FG120G... -> 120G).
    model = report.get("model")
    if not model and isinstance(ser, str):
        m = SERIAL_MODEL_RE.match(ser)
        model = m.group(1) if m else None
    nickname = f"Fortinet_CA_{model}" if model else "Fortinet_CA"
    doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": iso(datetime.now(timezone.utc)),
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "read_only": True},
        "source_report": report.get("_source"),
        "target": {"ip": report.get("ip"), "serial": ser, "model": model},
        "acquisition": {"vectors_tried": vectors_tried},
        "ca_candidates": [candidate_json(c) for c in all_cands],
        "selected_ca": ({"sha256": selected["sha256"], "pem_file": OUT_PEM}
                        if selected else None),
        "handoff": {"phase3": ({
            "nickname": nickname, "trust_flags": "C,,",
            "pem_file": OUT_PEM, "sha256": selected["sha256"],
            "expected_aki": pretty_hex(report.get("expected_aki")),
            "serial": ser, "model": model,
        } if selected else None)},
        "notes": notes,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return pem_path, json_path, doc


# =============================================================================
# 10. main()
# =============================================================================

def load_report(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        die(f"informe ilegible {path}: {exc}", 2)
    hosts = data.get("hosts") or []
    rep = {"_source": path}
    tgt = next((h for h in hosts if (h.get("tls") or {}).get("interceptor_suspected")),
               hosts[0] if hosts else {})
    dev = tgt.get("device") or {}
    tls = tgt.get("tls") or {}
    rep["ip"] = tgt.get("ip")
    rep["serial"] = dev.get("serial")
    rep["model"] = dev.get("model")
    rep["expected_aki"] = hexnorm(tls.get("aki"))
    rep["leaf"] = {"issuer": tls.get("issuer"), "aki": tls.get("aki"),
                   "subject": tls.get("subject")}
    return rep


def build_leaf_from_capture(certs_by_sni):
    """Hoja capturada en M3 para usarla como referencia de verificacion."""
    for sni, ders in certs_by_sni.items():
        if not ders:
            continue
        try:
            info = parse_cert(ders[0])
        except (DerError, IndexError):
            continue
        if info["key_alg"] or info["subject"]:
            return {"info": info, "raw_der": ders[0]}
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Adquiere y verifica la CA raiz del interceptor TLS Fortinet "
                    "(READ-ONLY). Produce fortinet_ca.pem + get_ca.json listos "
                    "para importar en la Fase 3.",
        epilog="No importa certificados ni modifica el sistema. Cero deps.")
    g = ap.add_argument_group("entrada")
    g.add_argument("--report", default=None,
                   help=f"informe JSON de Fase 1 (def.: buscar {DEFAULT_REPORT} en cwd)")
    g.add_argument("--target", metavar="IP", default=None,
                   help="IP del interceptor si no hay informe")
    g.add_argument("--expect-aki", metavar="HEX", default=None,
                   help="AKI esperado (pista dura); def.: el del informe o "
                        "el pin de la Fase 1")
    g.add_argument("--ports", default=",".join(map(str, TLS_PORTS)),
                   help="puertos TLS a probar (def.: %(default)s)")
    g.add_argument("--snis", default=",".join(REFRESH_SNIS),
                   help="SNI de dominios re-firmados para cross-check (def.: %(default)s)")
    g.add_argument("--timeout", type=float, default=2.0, help="timeout TCP/TLS (def. 2s)")
    g.add_argument("--user", default=None, help="credencial GUI admin (vector 6)")
    g.add_argument("--passwd", default=None, help="password GUI admin (vector 6)")
    o = ap.add_argument_group("salida")
    o.add_argument("--outdir", default=".", help="directorio de salida (def. cwd)")
    o.add_argument("--verbose", action="store_true", help="log a stderr")
    args = ap.parse_args(argv)
    global VERBOSE
    VERBOSE = args.verbose

    report = load_report(args.report or DEFAULT_REPORT) \
        if (args.report or os.path.isfile(DEFAULT_REPORT)) else None
    if not report and not args.target:
        die("sin informe y sin --target: nada que perfilar "
            f"(busque {DEFAULT_REPORT} en el directorio actual)", 2)
    if not report:
        report = {"_source": None, "ip": args.target, "serial": None,
                  "model": None, "expected_aki": None, "leaf": None}
    if args.target:
        report["ip"] = args.target

    expected_aki = hexnorm(args.expect_aki or report.get("expected_aki")
                           or EXPECTED_AKI_DEFAULT)
    report["expected_aki"] = expected_aki
    ports = tuple(int(p) for p in args.ports.split(",") if p.strip())
    snis = tuple(s.strip() for s in args.snis.split(",") if s.strip())

    vectors_tried = []
    all_raw = []

    # Vector 1 SIEMPRE (aunque solo devuelva la hoja: es dato de verificacion).
    tls_hits = vec_tls_chain(report["ip"], ports, snis, args.timeout, vectors_tried)
    all_raw += tls_hits
    first_detail = tls_hits[0]["detail"] if tls_hits else None
    hits_first = [h["der"] for h in tls_hits if h["detail"] == first_detail]
    leaf_ref = build_leaf_from_capture({"first": hits_first})

    # Vector 2: llavero SO.
    all_raw += vec_keychain(vectors_tried)
    # Vectores 3+4: portal HTML y rutas directas.
    all_raw += vec_portal_html(report["ip"], ports, args.timeout, vectors_tried)
    # Vector 5: almacenes locales.
    all_raw += vec_local_stores(vectors_tried)
    # Vector 6: GUI admin con creds.
    all_raw += vec_admin_gui(report["ip"], ports,
                             (args.user, args.passwd) if args.user else None,
                             args.timeout, vectors_tried)

    # Parsear y verificar cada candidato contra la hoja observada.
    notes = []
    cands = []
    for item in all_raw:
        try:
            info = parse_cert(item["der"])
        except (DerError, IndexError, binascii.Error) as exc:
            notes.append(f"candidato ilegible descartado ({item['vector']}): {exc}")
            continue
        item["info"] = info
        item["sha256"] = hashlib.sha256(item["der"]).hexdigest()
        item["raw_der"] = item["der"]
        checks, hard_ok, conf = verify_candidate(info, (leaf_ref or {}).get("info"),
                                                 expected_aki)
        checks["signature_valid"] = None
        checks["seen_in_chains"] = 1
        checks["confidence"] = round(conf, 2)
        item["verification"] = checks
        if hard_ok:
            cands.append(item)
        else:
            failed = [k for k in ("subject_issuer_match", "aki_ski_match",
                                  "ca_true", "self_signed", "valid_dates")
                      if not checks.get(k)]
            notes.append(f"descartado {item['sha256'][:12]} ({item['vector']}): "
                         f"fallan {failed}")

    ranked = dedupe_and_rank(cands)
    # Check blando: firma de la hoja contra la CA seleccionada + multi-cadena.
    selected = ranked[0] if ranked else None
    if selected and leaf_ref:
        sv = verify_leaf_signature(selected["info"], leaf_ref)
        selected["verification"]["signature_valid"] = sv
        for c in ranked:
            c["verification"]["signature_valid"] = (
                verify_leaf_signature(c["info"], leaf_ref)
                if c is not selected else sv)
    for c in ranked:
        c["verification"]["seen_in_chains"] = c["seen_in"]
        if c["seen_in"] >= 2:
            c["verification"]["confidence"] = min(
                round(c["verification"]["confidence"] + 0.02, 2), 1.0)

    pem_path, json_path, doc = write_outputs(args.outdir, report, selected,
                                             ranked, vectors_tried, notes)

    if selected:
        v = selected["verification"]
        print(f"CA seleccionada: {pretty_hex(selected['info'].get('ski'))} "
              f"sha256={selected['sha256']} confidence={v['confidence']}")
        print(f"PEM: {pem_path}\nJSON: {json_path}")
        return 0
    print("sin CA verificada: revisa acquisition.vectors_tried en get_ca.json",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
