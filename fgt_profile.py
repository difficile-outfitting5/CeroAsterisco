#!/usr/bin/env python3
"""fgt_profile - localizador y perfilador de interceptores TLS Fortinet.

Dado un target (o el gateway por defecto), localiza un FortiGate que hace
inspeccion SSL/TLS profunda, perfila el dispositivo (vendor/tipo/modelo/serial)
y emite un informe JSON con superficie de ataque y un hook offline a CVEs.

100% stdlib Python 3.10+. Sin root, sin dependencias, sin telemetria.
Las unicas llamadas de red van dirigidas al target explicito o deducido.
"""

from __future__ import annotations

import argparse
import binascii
import concurrent.futures
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
from datetime import datetime, timezone

# =============================================================================
# 1. CONSTANTES Y FIRMAS (tablas de datos, no codigo)
# =============================================================================

TOOL_NAME = "fgt_profile"
TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0"

DEFAULT_PORTS = (22, 80, 443, 541, 8008, 8443, 10443)
MAX_WORKERS = 16          # limite duro de conexiones vivas
BODY_LIMIT = 4096         # primeros 4 KB del body
MAX_REDIRECTS = 2
BANNER_BYTES = 128
CVE_FILENAME = "fortios_cve.json"

HTTP_PATHS = (
    ("/", "root"),
    ("/login", "gui_login"),
    ("/remote/login", "sslvpn_login"),
    ("/remote/fgt_lang?lang=", "fgt_lang"),
    ("/api/v2/cmdb/system/status", "api_status"),
)

BODY_MARKERS = (
    ("FortiToken", "body.FortiToken"),
    ("fgt_lang", "body.fgt_lang"),
    ("FortiGate", "body.FortiGate"),
    ("SSL-VPN", "body.SSL-VPN"),
)

ISSUER_VENDOR_RE = re.compile(r"(?i)\b(fortinet|fortigate)\b")
SERIAL_LIKE_RE = re.compile(r"^F[WG]", re.I)

SSH_BANNER_RE = re.compile(rb"SSH-[\d.]+-FortiSSH[_\s](\S+)", re.I)

TLS_VER_RE = re.compile(
    r"(?i)(?:FGT|FortiGate|FortiOS)[\s_-]*v?(\d+\.\d+(?:\.\d+)?)")

LOGIN_VER_RES = (
    re.compile(r"(?i)fortiOS[/_-]?v?(\d+\.\d+(?:\.\d+)?)"),
    re.compile(r"/service/([\d.]+)/"),  # assets versionados: /service/7.4.3/...
)

SERVER_VER_RE = re.compile(r"(?i)Forti[Gg]ate[/ ]?([\d.]+)")

# Prefijo de serial -> producto. El numero/letras del prefijo ES el modelo.
SERIAL_PREFIX_MAP = (
    (re.compile(r"^FWF", re.I), "FortiWiFi"),
    (re.compile(r"^FWB", re.I), "FortiWeb"),
    (re.compile(r"^FSA", re.I), "FortiSandbox"),
    (re.compile(r"^FMG", re.I), "FortiManager"),
    (re.compile(r"^FAZ", re.I), "FortiAnalyzer"),
    (re.compile(r"^FGT?", re.I), "FortiGate"),
)
MODEL_FROM_SERIAL_RE = re.compile(r"^F(?:W|G)?T?(\d+[A-Za-z0-9]*)", re.I)

PRE_AUTH_PATHS = ("/", "/login", "/remote/login", "/remote/fgt_lang?lang=")

# CN/O habituales de CAs publicas: si el issuer casa, NO es interceptor.
KNOWN_ROOT_CN_HINTS = (
    "ISRG", "Let's Encrypt", "DigiCert", "Sectigo", "COMODO", "GlobalSign",
    "Entrust", "Amazon", "Google Trust", "Microsoft", "Apple", "QuoVadis",
    "UserTrust", "SecureCore", "Starfield", "Telia", "Sonera", "CSCORP",
    "HARICA", "ACCV", "Izenpe", "ANF Secure Server",
)

COLORS = {"ok": "\033[32m", "warn": "\033[33m", "bad": "\033[31m",
          "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m"}

log = logging.getLogger(TOOL_NAME)

# =============================================================================
# 2. UTILIDADES PURAS (parsing, hashing, formateo)
# =============================================================================


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def colorize(text: str, tag: str, enabled: bool) -> str:
    if not enabled or not sys.stdout.isatty():
        return text
    return f"{COLORS.get(tag, '')}{text}{COLORS['reset']}"


def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """mmh3 x86-32 (variante de shodan icon-hash) implementada a mano."""
    c1, c2, nkey = 0xCC9E2D51, 0x1B873593, 0xE6546B64
    h1 = seed & 0xFFFFFFFF
    length = len(data)
    for i in range(0, length - (length % 4), 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + nkey) & 0xFFFFFFFF
    tail = data[length - (length % 4):]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 if h1 < 0x80000000 else h1 - 0x100000000


def der_oid_str(oid_bytes: bytes) -> str:
    """OID DER (sin TLV) -> forma punteada."""
    parts = [str((oid_bytes[0] // 80) * 40 + oid_bytes[0] % 80)]
    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _read_der_len(buf: bytes, pos: int):
    first = buf[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    nbytes = first & 0x7F
    total = int.from_bytes(buf[pos:pos + nbytes], "big")
    return total, pos + nbytes


def _parse_der_seq(buf: bytes, start: int, end: int):
    """Elementos TLV hijos de una secuencia ya acotada [(tag, value), ...]."""
    items = []
    pos = start
    while pos < end:
        t = buf[pos]
        l, vstart = _read_der_len(buf, pos + 1)
        vend = vstart + l
        items.append((t, buf[vstart:vend]))
        pos = vend
    return items


ATTR_OID_SHORT = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.8": "ST", "2.5.4.7": "L",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "0.9.2342.19200300.100.1.1": "UID",
}

SIG_ALG_NAMES = {
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsa-OAEP-sha1",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.113549.1.1.1": "rsaEncryption",
}


def _attr_value_text(value_tlv: bytes) -> str:
    """Texto de un AttributeValue (primer string del SET, decodificado)."""
    tag = value_tlv[0]
    l, vstart = _read_der_len(value_tlv, 1)
    raw = value_tlv[vstart:vstart + l]
    if tag == 0x0C:
        return raw.decode("utf-8", errors="replace")
    if tag in (0x16, 0x17):  # PrintableString / IA5String
        return raw.decode("ascii", errors="replace")
    if tag == 0x1E:  # BMPString
        try:
            return raw.decode("utf-16-be")
        except UnicodeError:
            return raw.hex()
    return raw.decode("utf-8", errors="replace")


def get_attr(attrs: dict, *keys: str) -> str | None:
    low = {k.lower(): v for k, v in attrs.items()}
    for k in keys:
        v = low.get(k.lower())
        if v:
            return v
    return None


def fmt_time(t: str | None) -> str | None:
    """UTCTime/GeneralizedTime DER -> ISO-ish legible. None si no hay."""
    if not t:
        return None
    m = re.match(r"(\d{2,4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?", t)
    if not m:
        return t
    g = [int(x) for x in m.groups()]
    if len(str(m.group(1))) == 2:
        g[0] += 2000 if g[0] < 50 else 1900
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % tuple(g)


# =============================================================================
# 3. CAPA DE RED (targeting, escaneo, banners)
# =============================================================================


def _run_cmd(argv: list[str]) -> str:
    """Solo comandos de enrutamiento/ARP del SO (justificado en M1)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def find_default_gateway() -> str | None:
    """macOS: `route -n get default` (campo gateway:). Linux: `ip route` (via).
    Fallback comun: `netstat -rn`."""
    gw_re = re.compile(r"^gateway:\s*(\S+)", re.M)
    via_re = re.compile(r"default\s+via\s+(\S+)")
    ns_re = re.compile(
        r"^(?:0\.0\.0\.0|default)\s+\S*\s*(\d{1,3}(?:\.\d{1,3}){3})", re.M)
    attempts = (
        (["route", "-n", "get", "default"], gw_re),
        (["ip", "route", "show", "default"], via_re),
        (["netstat", "-rn"], ns_re),
    )
    for argv, rx in attempts:
        out = _run_cmd(argv)
        m = rx.search(out) or re.search(r"gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})", out)
        if m:
            return m.group(1)
    return None


def arp_candidates(cidr: str) -> list[str]:
    """Hosts vistos por la tabla ARP del SO, filtrados por la subnet dada."""
    net = ipaddress.ip_network(cidr, strict=False)
    ips: list[str] = []
    for line in _run_cmd(["arp", "-an"]).splitlines():
        m = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line)
        if m:
            ip = m.group(1)
            if ip in net and ip not in ips:
                ips.append(ip)
    return sorted(ips, key=lambda s: tuple(int(p) for p in s.split(".")))


def tcp_probe(ip: str, port: int, timeout: float, read_banner: bool = False):
    """TCP connect(). Devuelve (abierto, banner) sin lanzar excepciones."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = b""
            if read_banner:
                try:
                    sock.settimeout(min(timeout, 1.0))
                    banner = sock.recv(BANNER_BYTES)
                except (OSError, ssl.SSLError):
                    pass
            return True, banner
    except OSError:
        return False, b""


def scan_ports(ip: str, ports: tuple[int, ...], timeout: float) -> dict[int, bytes]:
    """Escaneo connect() acotado a MAX_WORKERS. Devuelve {puerto: banner}."""
    found: dict[int, bytes] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(tcp_probe, ip, p, timeout, p == 22): p
                   for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = futures[fut]
            ok, banner = fut.result()
            if ok:
                found[port] = banner
    return found


def discover_hosts(cidr: str, ports: tuple[int, ...], timeout: float):
    """Barrido ligero: ARP como descubrimiento + sondeo TCP a puertos TLS."""
    hosts = arp_candidates(cidr)
    log.info("ARP devolvio %d hosts en %s", len(hosts), cidr)
    results = []
    check_ports = tuple(p for p in ports if p in (443, 8443)) or (443,)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(scan_ports, ip, check_ports, timeout): ip
                   for ip in hosts}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            openmap = fut.result()
            if openmap:
                results.append({"ip": ip, "reason": "arp+tcp_open",
                                "ports": sorted(openmap)})
    return sorted(results, key=lambda h: tuple(int(p) for p in h["ip"].split(".")))


# =============================================================================
# 4. CAPA TLS (obtencion y parseo de certificado)
# =============================================================================


def make_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Queremos VER el cert roto del interceptor, no que el handshake falle.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _parse_name(seq_der: bytes) -> dict:
    out: dict[str, str] = {}
    for rdn_tlv in _parse_der_seq(seq_der, 0, len(seq_der)):
        for atv in _parse_der_seq(rdn_tlv[1], 0, len(rdn_tlv[1])):
            pair = _parse_der_seq(atv[1], 0, len(atv[1]))
            oid = der_oid_str(pair[0][1])
            short = ATTR_OID_SHORT.get(oid, oid)
            out[short] = _attr_value_text(pair[1])
    return out


def _spki_key_alg(spki_der: bytes) -> str | None:
    alg = _parse_der_seq(spki_der, 0, len(spki_der))[0][1]
    oid = der_oid_str(_parse_der_seq(alg, 0, len(alg))[0][1])
    return SIG_ALG_NAMES.get(oid, oid)


def parse_cert_der(der: bytes) -> dict:
    """X.509 minimo sobre DER: subject/issuer/SAN/AKI/SKI/fechas/alg clave."""
    out: dict = {"subject": {}, "issuer": {}, "san": [], "aki": None,
                 "ski": None, "key_alg": None, "serial_hex": None,
                 "not_before": None, "not_after": None}
    try:
        cert = _parse_der_seq(der, 0, len(der))[0][1]
        tbs = _parse_der_seq(cert, 0, len(cert))[0][1]
        els = _parse_der_seq(tbs, 0, len(tbs))
        pos = 0
        if els[pos][0] == 0xA0:  # [0] version
            pos += 1
        out["serial_hex"] = format(int.from_bytes(els[pos][1], "big"), ":X"). \
            replace(":", "").upper() if els[pos][1] else None
        pos += 2  # saltamos serial y signature algorithm del TBS
        out["issuer"] = _parse_name(els[pos][1]); pos += 1
        out["subject"] = _parse_name(els[pos][1]); pos += 1
        times = _parse_der_seq(els[pos][1], 0, len(els[pos][1]))
        out["not_before"] = fmt_time(times[0][1].decode(errors="replace"))
        out["not_after"] = fmt_time(times[1][1].decode(errors="replace"))
        pos += 1
        out["key_alg"] = _spki_key_alg(els[pos][1]); pos += 1
        for t, v in els[pos:]:
            if t != 0xA3:  # extensions
                continue
            for ext in _parse_der_seq(v, 0, len(v)):
                e = _parse_der_seq(ext[1], 0, len(ext[1]))
                oid = der_oid_str(e[0][1])
                payload = e[-1][1]
                if oid == "2.5.29.17":  # SAN
                    for g in _parse_der_seq(payload, 0, len(payload)):
                        if g[0] == 0x82:
                            out["san"].append(g[1].decode(errors="replace"))
                elif oid == "2.5.29.35":  # AKI
                    inner = _parse_der_seq(payload, 0, len(payload))
                    out["aki"] = ":".join(f"{b:02X}" for b in inner[0][1]).upper()
                elif oid == "2.5.29.14":  # SKI
                    out["ski"] = ":".join(f"{b:02X}" for b in payload).upper()
    except (IndexError, ValueError, binascii.Error) as exc:
        log.debug("fallo parseo DER: %s", exc)
    return out


def grab_tls(ip: str, port: int, timeout: float, sni: str | None) -> dict | None:
    """Handshake TLS sin verificacion; devuelve dict crudo o None."""
    ctx = make_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version()
                cipher = tls.cipher()[0] if tls.cipher() else None
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    parsed = parse_cert_der(der)
    return {
        "der": der,
        "sha256": hashlib.sha256(der).hexdigest(),
        "tls_version": version,
        "cipher": cipher,
        **parsed,
    }


def analyze_tls(raw: dict) -> dict:
    """Normaliza el dict de grab_tls al contrato JSON de salida."""
    issuer = raw.get("issuer", {})
    org = get_attr(issuer, "O") or ""
    cn = get_attr(issuer, "CN") or ""
    ou = get_attr(issuer, "OU") or ""
    vendor_hit = bool(ISSUER_VENDOR_RE.search(f"{org} {cn} {ou}"))
    blob = f"{cn} {org}"
    public_ca = any(h.lower() in blob.lower() for h in KNOWN_ROOT_CN_HINTS)
    serial = ou or get_attr(issuer, "serialNumber")
    suspected = bool(vendor_hit or (not public_ca and serial
                                    and SERIAL_LIKE_RE.match(serial)))
    return {
        "subject": raw.get("subject", {}),
        "issuer": issuer,
        "san": raw.get("san", []),
        "aki": raw.get("aki"),
        "ski": raw.get("ski"),
        "serial_hex": raw.get("serial_hex"),
        "not_before": raw.get("not_before"),
        "not_after": raw.get("not_after"),
        "key_alg": raw.get("key_alg"),
        "sha256": raw.get("sha256"),
        "tls_version": raw.get("tls_version"),
        "cipher": raw.get("cipher"),
        "interceptor_suspected": suspected,
        "serial_from_ou": serial if SERIAL_LIKE_RE.match(serial or "") else None,
    }


# =============================================================================
# 5. CAPA HTTP (headers, redirects, body markers, favicon)
# =============================================================================


class HttpProbe:
    """Cliente HTTPS/HTTP minimo, contexto sin verificacion, <=2 redirects."""

    def __init__(self, host: str, port: int, use_tls: bool, timeout: float):
        self.host, self.port, self.timeout = host, port, timeout
        self.use_tls = use_tls

    def _conn(self):
        if self.use_tls:
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout,
                context=make_context())
        return http.client.HTTPConnection(self.host, self.port,
                                         timeout=self.timeout)

    def fetch(self, path: str) -> dict | None:
        url = path
        last: dict | None = None
        for _ in range(MAX_REDIRECTS + 1):
            try:
                conn = self._conn()
                conn.request("GET", url, headers={
                    "Host": self.host,
                    "User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
                resp = conn.getresponse()
                headers = {k.lower(): v for k, v in resp.getheaders()}
                body = resp.read(BODY_LIMIT)
                status = resp.status
                conn.close()
            except (OSError, http.client.HTTPException, ssl.SSLError):
                return last
            loc = headers.get("location")
            if status in (301, 302, 303, 307, 308) and loc:
                url = loc if loc.startswith("/") else "/" + loc
                last = {"status": status, "headers": headers, "body": b"",
                        "final_path": url, "redirected": True}
                continue
            return {"status": status, "headers": headers, "body": body,
                    "final_path": url}
        return last


def probe_http(ip: str, port: int, use_tls: bool, timeout: float) -> dict:
    """Recorre las rutas caracteristicas y acumula evidencia."""
    results: dict[str, dict] = {}
    markers: set[str] = set()
    cookies: set[str] = set()
    www_auth = server_hdr = powered = None
    sslvpn_seen = False
    bodies: list[str] = []
    for path, label in HTTP_PATHS:
        r = HttpProbe(ip, port, use_tls, timeout).fetch(path)
        if not r:
            continue
        headers, body = r["headers"], r["body"]
        for name, val in headers.items():
            low_val = val.lower()
            if name == "www-authenticate":
                www_auth = val
                if "fortigate" in low_val:
                    markers.add("http.header.WWW-Authenticate")
            elif name == "server":
                server_hdr = val
                if "fortinet" in low_val or "fortigate" in low_val:
                    markers.add("http.header.Server")
            elif name == "x-powered-by" and "fortinet" in low_val:
                powered = val
                markers.add("http.header.Powered-By-Fortinet")
            elif name == "set-cookie":
                m = re.match(r"\s*([^=;]+)=", val)
                if m:
                    cname = m.group(1).lower()
                    cookies.add(cname)
                    if cname.startswith("ftnt_"):
                        markers.add("http.cookie.ftnt_")
        text = body.decode("utf-8", errors="replace")
        bodies.append(text)
        for needle, tag in BODY_MARKERS:
            if needle.lower() in text.lower():
                markers.add(tag)
        if 'top.location="/login"' in text:
            markers.add("http.redirect.login")
        if r.get("redirected") and r["headers"].get("location") == "/login":
            markers.add("http.redirect.login")
        if path.startswith("/remote/"):
            sslvpn_seen = True
        results[label] = {"path": path, "status": r["status"],
                          "final_path": r.get("final_path")}
    fav_hash = None
    fav = HttpProbe(ip, port, use_tls, timeout).fetch("/favicon.ico")
    if fav and fav["status"] == 200 and fav["body"]:
        fav_hash = mmh3_x86_32(fav["body"])
    return {
        "results": results,
        "markers": sorted(markers),
        "cookies": sorted(cookies),
        "www_authenticate": www_auth,
        "server": server_hdr,
        "powered_by": powered,
        "sslvpn_seen": sslvpn_seen,
        "favicon_mmh3": fav_hash,
        "page_text": "\n".join(bodies)[:2 * BODY_LIMIT],
    }


# =============================================================================
# 6. CLASIFICADOR (match de firmas -> device/model/serial)
# =============================================================================


def serial_to_product(serial: str):
    """Prefijo de serial -> (producto, modelo). Desconocido: (None, None)."""
    for rx, product in SERIAL_PREFIX_MAP:
        if rx.match(serial):
            m = MODEL_FROM_SERIAL_RE.match(serial)
            model = m.group(1) if (m and product == "FortiGate") else None
            return product, model
    return None, None


def classify(http_info: dict, tls_norm: dict | None, ssh_banner: bytes) -> dict:
    """Aplica la tabla de firmas. NUNCA inventa: sin evidencia, null."""
    evidences: list[str] = []
    score = 0.0
    serial = None

    if tls_norm:
        if tls_norm.get("interceptor_suspected"):
            serial = tls_norm.get("serial_from_ou")
            if serial:
                evidences.append("tls.issuer.OU")
                score += 0.5
            else:
                evidences.append("tls.issuer.vendor")
                score += 0.3
        if "http.header.WWW-Authenticate" in http_info["markers"]:
            evidences.append("http.header.WWW-Authenticate")
            score += 0.3
    if "http.header.Powered-By-Fortinet" in http_info["markers"]:
        evidences.append("http.header.PoweredBy")
        score += 0.2
    if "http.header.Server" in http_info["markers"]:
        evidences.append("http.header.Server")
        score += 0.2
    if "http.cookie.ftnt_" in http_info["markers"]:
        evidences.append("http.cookie.ftnt_")
        score += 0.2
    if "http.redirect.login" in http_info["markers"]:
        evidences.append("http.redirect.login")
        score += 0.15
    for m in http_info["markers"]:
        if m.startswith("body."):
            evidences.append(m)
    if any(m.startswith("body.") for m in http_info["markers"]):
        score += 0.2
    if http_info["sslvpn_seen"] and any(
            m.startswith("body.") or "redirect" in m
            for m in http_info["markers"]):
        # /remote/* solo cuenta si ADEMAS hay contenido Fortinet: evita marcar
        # cualquier nginx con /remote/.
        evidences.append("http.path.remote")
        score += 0.15
    if ssh_banner and SSH_BANNER_RE.search(ssh_banner):
        evidences.append("ssh.banner.FortiSSH")
        score += 0.4

    if not evidences:
        return {"vendor": None, "type": None, "model": None, "serial": None,
                "confidence": 0.0, "evidence": []}

    product = model = None
    if serial:
        product, model = serial_to_product(serial)
        if product is None:
            # prefijo desconocido: guardamos serial crudo, model=null
            product = None
    conf = min(1.0, round(score, 2))
    return {
        "vendor": "Fortinet",
        "type": product,
        "model": model,
        "serial": serial,
        "confidence": conf,
        "evidence": sorted(set(evidences)),
    }


# =============================================================================
# 7. RESOLUCION DE VERSION (fuentes ordenadas por fiabilidad decreciente)
# =============================================================================


def resolve_versions(ssh_banner: bytes, tls_raw: dict | None,
                     http_info: dict) -> list[dict]:
    """Candidatos {version, source, confidence}. Lista vacia si no hay datos."""
    cands: list[dict] = []

    m = SSH_BANNER_RE.search(ssh_banner) if ssh_banner else None
    if m:
        cands.append({"version": m.group(1).decode(errors="replace"),
                      "source": "ssh_banner", "confidence": 0.9})

    if tls_raw:
        blob = json.dumps({"i": tls_raw.get("issuer"),
                           "s": tls_raw.get("subject")})
        m = TLS_VER_RE.search(blob)
        if m:
            cands.append({"version": m.group(1), "source": "tls_metadata",
                          "confidence": 0.5})

    text = http_info.get("page_text", "")
    for rx in LOGIN_VER_RES:
        m = rx.search(text)
        if m:
            cands.append({"version": m.group(1),
                          "source": "login_page_assets", "confidence": 0.4})
            break

    srv = http_info.get("server")
    if srv:
        m = SERVER_VER_RE.search(srv)
        if m:
            cands.append({"version": m.group(1),
                          "source": "http.header.Server", "confidence": 0.6})

    seen: set[tuple] = set()
    uniq = []
    for c in cands:
        key = (c["version"], c["source"])
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq


# =============================================================================
# 8. HOOK CVE OFFLINE (lectura de JSON local si existe)
# =============================================================================


def load_cve_db() -> dict:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        CVE_FILENAME)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            db = json.load(fh)
        return db if isinstance(db, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("no se pudo leer %s: %s", CVE_FILENAME, exc)
        return {}


def _ver_tuple(v: str):
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:3]) if nums else None


def _in_range(ver: str, rng: str) -> bool:
    """Rangos tipo '>=7.2.0 <7.2.5 || >=7.4.0 <7.4.3' o '7.2.x'."""
    t = _ver_tuple(ver)
    if not t:
        return False
    for alt in rng.split("||"):
        clauses = re.findall(r"(>=|<=|==|!=|>|<|=)?\s*([\d][\d.]*)", alt)
        if not clauses:
            continue
        ok = True
        for op, bound_s in clauses:
            bound = _ver_tuple(bound_s)
            if bound is None:
                continue
            if ".x" in bound_s or len(bound) < len(t):
                # prefijo: 7.2.x matchea 7.2.*
                pre = bound
                tt = t[:len(pre)]
                if op in ("", "=", "=="):
                    if tt != pre:
                        ok = False
                else:
                    ok = _cmp_op(op, t, bound)
            else:
                if not _cmp_op(op or "=", t, bound):
                    ok = False
        if ok:
            return True
    return False


def _cmp_op(op: str, t: tuple, b: tuple) -> bool:
    n = max(len(t), len(b))
    tt = t + (0,) * (n - len(t))
    bb = b + (0,) * (n - len(b))
    return {">=": tt >= bb, "<=": tt <= bb, ">": tt > bb, "<": tt < bb,
            "=": tt == bb, "==": tt == bb, "!=": tt != bb}[op]


def match_cves(db: dict, product: str | None, versions: list[dict]) -> list[dict]:
    if not db or not product:
        return []
    entries = db.get(product) or db.get("FortiGate") or []
    matches = []
    for cand in versions:
        for item in entries:
            if _in_range(cand["version"], item.get("range", "")):
                matches.append({**item, "matched_version": cand["version"],
                                "matched_source": cand["source"]})
    return matches


# =============================================================================
# 9. SALIDA (JSON + resumen humano)
# =============================================================================


def build_attack_surface(device: dict, http_info: dict, tls_norm: dict | None,
                         open_ports: list[int], ip: str) -> dict:
    admin_ui = None
    for p in (443, 8443, 10443):
        if p in open_ports and (device.get("evidence") or tls_norm):
            admin_ui = f"https://{ip}/login" if p == 443 \
                else f"https://{ip}:{p}/login"
            break
    pre_auth = []
    for res in http_info.get("results", {}).values():
        st = res.get("status")
        path = res.get("path")
        if st and path in PRE_AUTH_PATHS and st in (200, 302, 401, 403):
            pre_auth.append(f"{path} -> {st}")
        elif st and path == "/api/v2/cmdb/system/status" and st != 404:
            pre_auth.append(f"{path} -> {st} (alcanzable)")
    notes = []
    if tls_norm and tls_norm.get("interceptor_suspected"):
        notes.append("MITM TLS activo: los certs los re-firma el dispositivo; "
                     "la prioridad ofensiva es la CA auto-firmada (proteccion "
                     "del trust anchor, export del root cert, integridad de "
                     "su clave privada en el FortiGate).")
    if http_info.get("sslvpn_seen"):
        notes.append("Portal SSL VPN alcanzable (/remote/login): superficie "
                     "pre-auth clasica de FortiOS (verificar contra base CVE "
                     "local, ej. familia CVE-2022-42475).")
    if 22 in open_ports:
        notes.append("SSH abierto en interfaz de gestion: si el banner filtra "
                     "FortiSSH_<ver>, da firmware exacto para correlacion.")
    if any("api" in p for p in pre_auth):
        notes.append("Endpoint /api/* responde (no-404): comprobar acceso sin "
                     "token antes de asumir autenticacion obligatoria.")
    notes.append("Por donde empezar: hash SHA-256 de la CA del interceptor, "
                 "endpoints /api sin auth, portal /remote/login, y exposicion "
                 "de 8443/admin https frente a WAN.")
    return {"admin_ui": admin_ui, "ssl_vpn": bool(http_info.get("sslvpn_seen")),
            "pre_auth_endpoints": pre_auth, "notes": notes}


def profile_host(ip: str, ports: tuple[int, ...], timeout: float,
                 sni: str | None, cve_db: dict) -> dict:
    log.info("perfilando %s", ip)
    openmap = scan_ports(ip, ports, timeout)
    open_ports = sorted(openmap)
    ssh_banner = openmap.get(22, b"")
    host = {"ip": ip, "open_ports": open_ports,
            "device": {"vendor": None, "type": None, "model": None,
                       "serial": None, "confidence": 0.0, "evidence": []},
            "firmware": {"candidates": []},
            "tls": None, "http": None, "attack_surface": None,
            "cve_matches": []}
    if not open_ports:
        host["attack_surface"] = build_attack_surface(
            host["device"], {"results": {}, "markers": [], "cookies": [],
                             "sslvpn_seen": False, "favicon_mmh3": None,
                             "page_text": "", "server": None},
            None, open_ports, ip)
        return host

    tls_raw = None
    tls_port = next((p for p in (443, 8443, 10443) if p in openmap), None)
    if tls_port:
        tls_raw = grab_tls(ip, tls_port, timeout, sni)
    tls_norm = analyze_tls(tls_raw) if tls_raw else None

    http_port = next((p for p in (443, 8443, 10443, 80, 8008) if p in openmap),
                     None)
    http_info = {"results": {}, "markers": [], "cookies": [],
                 "www_authenticate": None, "server": None, "powered_by": None,
                 "sslvpn_seen": False, "favicon_mmh3": None, "page_text": ""}
    if http_port:
        http_info = probe_http(ip, http_port,
                               http_port not in (80, 8008), timeout)

    device = classify(http_info, tls_norm, ssh_banner)
    versions = resolve_versions(ssh_banner, tls_raw, http_info)
    root_res = http_info["results"].get("root") or {}
    host.update({
        "device": device,
        "firmware": {"candidates": versions},
        "tls": tls_norm,
        "http": {
            "status": root_res.get("status", 0),
            "headers": (http_info["results"].get("root") or {}).get(
                "headers", {}) if False else {
                "Server": http_info.get("server"),
                "WWW-Authenticate": http_info.get("www_authenticate"),
                "X-Powered-By": http_info.get("powered_by"),
            },
            "cookies": http_info["cookies"],
            "markers": http_info["markers"],
            "paths": http_info["results"],
            "favicon_mmh3": http_info["favicon_mmh3"],
        },
        "attack_surface": build_attack_surface(device, http_info, tls_norm,
                                               open_ports, ip),
        "cve_matches": match_cves(cve_db, device.get("type"), versions),
    })
    return host


def render_human(report: dict, use_color: bool) -> str:
    lines = [f"# {TOOL_NAME} {TOOL_VERSION} — generated {report['generated_at']}"]
    if not report["hosts"]:
        lines.append(colorize("Sin candidatos.", "dim", use_color))
        return "\n".join(lines)
    for h in report["hosts"]:
        d = h["device"] or {}
        head = f"== {h['ip']} ({h.get('reason', 'target')}) =="
        if d.get("vendor"):
            head += (f"  {d['vendor']} {d.get('type') or '?'} "
                     f"{d.get('model') or ''} serial={d.get('serial') or 'null'} "
                     f"conf={d.get('confidence')}")
        else:
            head += "  sin evidencia Fortinet"
        lines.append(colorize(head, "ok" if d.get("vendor") else "warn",
                              use_color))
        lines.append(f"   puertos abiertos: {h['open_ports'] or 'ninguno'}")
        tls = h.get("tls")
        if tls:
            mark = "INTERCEPTOR SOSPECHADO" if tls["interceptor_suspected"] \
                else "issuer normal"
            lines.append(colorize(
                f"   TLS issuer CN={tls['issuer'].get('CN')} "
                f"O={tls['issuer'].get('O')} OU={tls['issuer'].get('OU')} "
                f"[{mark}] AKI={tls['aki']} sha256={tls['sha256']}",
                "bad" if tls["interceptor_suspected"] else "dim", use_color))
        fw = (h.get("firmware") or {}).get("candidates", [])
        if fw:
            lines.append("   firmware: " + ", ".join(
                f"{c['version']} ({c['source']}, {c['confidence']})"
                for c in fw))
        if h.get("cve_matches"):
            for cv in h["cve_matches"]:
                lines.append(colorize(
                    f"   CVE {cv['cve']} cvss={cv.get('cvss')} "
                    f"auth={cv.get('auth')}", "bad", use_color))
        for note in (h.get("attack_surface") or {}).get("notes", []):
            lines.append(f"   * {note}")
    return "\n".join(lines)


# =============================================================================
# 10. main() con argparse
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Localiza y perfila interceptores TLS Fortinet (FortiGate) "
                    "en la red local. Sin root, sin dependencias, sin "
                    "telemetria: solo sockets TCP hacia el target.",
        epilog="Ejemplos: %(prog)s --target 192.168.1.1 ; "
               "%(prog)s --scan-cidr 192.168.1.0/24 --json out.json ; "
               "%(prog)s --color . Coloca fortios_cve.json junto al script "
               "para matching offline de CVEs. Exit codes: 0 hallazgo, 1 nada, "
               "2 error de uso.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--target", metavar="IP",
                   help="IP explicita del sospechoso (maxima prioridad).")
    g.add_argument("--scan-cidr", metavar="CIDR",
                   help="Barrido ligero de una subnet (ARP + TCP 443/8443), "
                        "ej. 192.168.1.0/24.")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help="Puertos TCP a probar, lista CSV (def: %(default)s).")
    p.add_argument("--timeout", type=float, default=1.5,
                   help="Timeout por connect/handshake en segundos "
                        "(def: %(default)s).")
    p.add_argument("--sni", metavar="HOST",
                   help="ServerName TLS opcional (si quieres ver el cert que "
                        "el interceptor genera para un dominio concreto).")
    p.add_argument("--json", nargs="?", const="-", metavar="RUTA",
                   help="Salida JSON a stdout (o a RUTA si se da).")
    p.add_argument("--color", action="store_true",
                   help="Colorear el resumen humano (solo si stdout es TTY).")
    p.add_argument("--verbose", action="store_true",
                   help="Log de progreso minimo por stderr.")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.ERROR,
                        format="%(levelname)s %(message)s", stream=sys.stderr)
    try:
        ports = tuple(sorted({int(x) for x in args.ports.split(",") if x}))
    except ValueError:
        print(f"error: lista de puertos invalida: {args.ports}",
              file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("error: --timeout debe ser > 0", file=sys.stderr)
        return 2

    targets: list[tuple[str, str]] = []
    if args.target:
        try:
            ipaddress.ip_address(args.target)
        except ValueError:
            print(f"error: --target no es una IP valida: {args.target}",
                  file=sys.stderr)
            return 2
        targets = [(args.target, "--target explicito")]
    elif args.scan_cidr:
        try:
            ipaddress.ip_network(args.scan_cidr, strict=False)
        except ValueError:
            print(f"error: --scan-cidr invalido: {args.scan_cidr}",
                  file=sys.stderr)
            return 2
        found = discover_hosts(args.scan_cidr, ports, args.timeout)
        targets = [(h["ip"], h["reason"]) for h in found]
    else:
        gw = find_default_gateway()
        if not gw:
            print("error: no se pudo deducir el gateway por defecto; usa "
                  "--target o --scan-cidr", file=sys.stderr)
            return 1
        targets = [(gw, "gateway por defecto deducido")]
        log.info("gateway deducido: %s", gw)

    if not targets:
        print("No se encontro ningun candidato en el barrido.",
              file=sys.stderr)
        return 1

    cve_db = load_cve_db()
    hosts = []
    for ip, reason in targets:
        log.info("candidato %s (%s)", ip, reason)
        h = profile_host(ip, ports, args.timeout, args.sni, cve_db)
        h["reason"] = reason
        hosts.append(h)

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso(),
        "scanner": {"name": TOOL_NAME, "version": TOOL_VERSION,
                    "root_required": False},
        "hosts": hosts,
    }

    found_any = any(h["device"] and h["device"].get("vendor") for h in hosts)

    if args.json is not None:
        text = json.dumps(report, indent=2, ensure_ascii=False, default=str)
        if args.json == "-":
            print(text)
        else:
            try:
                with open(args.json, "w", encoding="utf-8") as fh:
                    fh.write(text + "\n")
                print(f"JSON escrito en {args.json}", file=sys.stderr)
            except OSError as exc:
                print(f"error escribiendo {args.json}: {exc}", file=sys.stderr)
                return 2
    else:
        print(render_human(report, args.color))

    if not found_any:
        print("Nota: ningún host mostro evidencia Fortinet.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
