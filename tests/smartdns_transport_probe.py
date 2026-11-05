"""Read-only direct TCP/TLS/DoH probe; never uses environment/system/local proxies."""
import base64, concurrent.futures, http.client, json, pathlib, socket, ssl, struct, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / '.test-results' / 'transport-test3'
OUT.mkdir(parents=True, exist_ok=True)
CTX = ssl.create_default_context()

def query(host, kind=1, ident=0):
    return struct.pack('!6H', ident, 256, 1, 0, 0, 0) + b''.join(bytes([len(p)]) + p.encode('ascii') for p in host.split('.')) + b'\0' + struct.pack('!2H', kind, 1)

def addresses(data):
    def skip(p):
        while data[p]:
            if data[p] & 192 == 192: return p + 2
            p += data[p] + 1
        return p + 1
    p = skip(12) + 4
    result = []
    for _ in range(struct.unpack_from('!H', data, 6)[0]):
        p = skip(p)
        kind, _, _, size = struct.unpack_from('!HHIH', data, p)
        p += 10
        if kind == 1 and size == 4: result.append(socket.inet_ntop(socket.AF_INET, data[p:p+size]))
        if kind == 28 and size == 16: result.append(socket.inet_ntop(socket.AF_INET6, data[p:p+size]))
        p += size
    return result

class Pinned(http.client.HTTPSConnection):
    def __init__(self, host, ip):
        super().__init__(host, timeout=3, context=CTX)
        self.ip, self.stage = ip, 'TCP'
    def connect(self):
        self.sock = socket.create_connection((self.ip, 443), timeout=3)
        self.stage = 'TLS'
        self.sock = CTX.wrap_socket(self.sock, server_hostname=self.host)
        self.stage = 'HTTP'
        self.sock.settimeout(5)

def request(label, host, ip, method, payload, path='/dns-query', agent=None):
    start = time.monotonic()
    conn = Pinned(host, ip)
    result = dict(label=label, host=host, ip=ip, method=method, wire=payload.hex())
    try:
        headers = {'Accept': 'application/dns-message'}
        body = None
        if method == 'POST':
            headers['Content-Type'] = 'application/dns-message'
            body = payload
        else:
            path += '?dns=' + base64.urlsafe_b64encode(payload).decode().rstrip('=')
        if agent: headers['User-Agent'] = agent
        result.update(path=path, requestHeaders=headers)
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read(65536)
        result.update(status=response.status, responseHeaders=dict(response.getheaders()), peer=conn.ip)
        if response.status == 200 and response.getheader('Content-Type', '').split(';')[0] == 'application/dns-message':
            result.update(addresses=addresses(data), responseWire=data.hex())
        else: result['body'] = data[:2048].decode('utf-8', 'replace')
    except Exception as error: result.update(stage=conn.stage, error=type(error).__name__ + ': ' + str(error))
    finally: conn.close()
    result['ms'] = round((time.monotonic() - start) * 1000)
    return result

def transport(item):
    host, ip = item
    start = time.monotonic()
    result = dict(host=host, ip=ip, stage='TCP')
    try:
        with socket.create_connection((ip, 443), timeout=3) as sock:
            result['tcpMs'] = round((time.monotonic() - start) * 1000)
            result['stage'] = 'TLS'
            with CTX.wrap_socket(sock, server_hostname=host) as tls:
                result.update(stage='TLS_OK', protocol=tls.version(), certificate=tls.getpeercert())
    except Exception as error: result['error'] = type(error).__name__ + ': ' + str(error)
    result['ms'] = round((time.monotonic() - start) * 1000)
    return result

def main():
    peers = [('d.webshiftvpn.ru', '31.31.207.68'), ('dns.dns-ai.ru', '194.87.196.13'), ('dns.dns-ai.ru', '45.151.102.219'), ('geohide.ru', '159.194.200.33')]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: transports = list(pool.map(transport, peers))
    minimal = query('chatgpt.com')
    app = (OUT / 'app-query.bin').read_bytes()
    tests = [request('webshift-' + label + '-' + method, peers[0][0], peers[0][1], method, wire)
             for label, wire in [('minimal-id0', minimal), ('app-wire', app)] for method in ['GET', 'POST']]
    tests.append(request('webshift-browser-UA', peers[0][0], peers[0][1], 'POST', minimal, agent='Mozilla/5.0'))
    # Ordinary resolver: baseline and endpoint bootstrap validation ONLY, never app failover.
    for host in ['chatgpt.com', 'gemini.google.com', 'd.webshiftvpn.ru', 'dns.dns-ai.ru', 'geohide.ru']:
        tests.append(request('baseline-' + host, 'cloudflare-dns.com', '1.1.1.1', 'POST', query(host)))
    report = dict(utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), vpnAbsence='NOT_VERIFIED', proxies='NONE; raw sockets', transports=transports, requests=tests)
    (OUT / 'probe.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    if '--proxy-v6' in sys.argv:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(transport, [('chatgpt.com', '2a12:bec4:1bb0:2a30::2'), ('gemini.google.com', '2a12:bec4:1bb0:2a30::2')]))
        (OUT / 'proxy-v6.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(results, ensure_ascii=False, indent=2))
    elif '--geohide-pool' in sys.argv:
        def check_pool(ip):
            result = transport(('geohide.ru', ip))
            if result['stage'] == 'TLS_OK':
                result['doh'] = request('geohide-current-pool', 'geohide.ru', ip, 'POST', query('chatgpt.com'))
            return result
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(check_pool, ['193.233.112.67', '193.233.112.88', '193.233.112.130', '37.230.192.51']))
        (OUT / 'geohide-pool.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        main()
