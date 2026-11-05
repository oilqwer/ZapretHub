"""Bounded follow-up; previous TLS failures are reused rather than repeated."""
import concurrent.futures, json, pathlib, time
import smartdns_transport_probe as probe

OUT = probe.ROOT / '.test-results' / 'provider-cycle'
OUT.mkdir(parents=True, exist_ok=True)
END = time.monotonic() + 120
results, bootstrap, baseline = [], [], {}

def resolve(host, kind=1):
    row = probe.request('bootstrap-only', 'cloudflare-dns.com', '1.1.1.1', 'POST', probe.query(host, kind))
    row.update(queryHost=host, queryType=kind)
    bootstrap.append(row)
    return row.get('addresses', [])

def pinned_https(host, ip):
    conn = probe.Pinned(host, ip)
    start = time.monotonic()
    result = dict(host=host, ip=ip)
    try:
        conn.request('GET', '/app?hl=en' if host == 'gemini.google.com' else '/', headers={'Accept-Language': 'en', 'User-Agent': 'Mozilla/5.0'})
        response = conn.getresponse()
        body = response.read(131072).decode('utf-8', 'replace')
        lower = body.lower()
        result.update(status=response.status, location=response.getheader('Location'), certificateVerified=True,
                      regionMarker=any(x in lower for x in ['unsupported_country', 'not supported in your country', 'not available in your country']),
                      denialMarker=any(x in lower for x in ['unable to load site', 'you have been blocked']),
                      applicationAccess='UNVERIFIED: no authenticated AI request was made')
    except Exception as error: result.update(stage=conn.stage, error=str(error))
    finally: conn.close()
    result['ms'] = round((time.monotonic() - start) * 1000)
    return result

def check(item):
    provider, host, ip = item
    result = dict(provider=provider, host=host, ip=ip, transport=probe.transport((host, ip)), dns=[], https=[])
    if result['transport']['stage'] != 'TLS_OK':
        result['skipped'] = 'GET/POST/A/AAAA/proxy checks: TLS prerequisite failed; no repeat'
        return result
    for service in ['chatgpt.com', 'gemini.google.com']:
        for kind in [1, 28]:
            if time.monotonic() >= END: result['deadline'] = True; return result
            wire = probe.query(service, kind)
            # Both methods tested once. Later queries use the first supported method.
            methods = ['GET', 'POST'] if not result['dns'] else [result['method']]
            successes = []
            for method in methods:
                row = probe.request(provider, host, ip, method, wire)
                row.update(service=service, type=kind)
                other = baseline.get((service, kind), [])
                row['comparison'] = 'NO_COMPARISON' if not row.get('addresses') or not other else ('SAME_NOT_PROXY_PROOF' if set(row['addresses']) == set(other) else 'DIFFERENT_CANDIDATE_NOT_PROXY_PROOF')
                result['dns'].append(row)
                if row.get('status') == 200 and 'addresses' in row: successes.append(row)
            if not successes: return result
            result['method'] = successes[0]['method']
            if kind == 1:
                for address in successes[0].get('addresses', [])[:1]:
                    result['https'].append(pinned_https(service, address))
    return result

def batch(provider, host, ips):
    items = [(provider, host, ip) for ip in dict.fromkeys(ips)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(check, items))
    results.extend(rows)
    return any(row.get('https') and len(row['dns']) >= 4 for row in rows)

comss_ips = list(dict.fromkeys(['195.133.25.16', '212.109.221.20', '212.109.195.93'] + resolve('dns.comss.one')))
for service in ['chatgpt.com', 'gemini.google.com']:
    for kind in [1, 28]: baseline[(service, kind)] = resolve(service, kind)
comss_ok = batch('Comss.one', 'dns.comss.one', comss_ips)
if not comss_ok and time.monotonic() < END:
    batch('Malw.link', 'dns.malw.link', ['179.254.166.171', '164.5.224.81'])
    gateway = '5u35p8m9i7.cloudflare-gateway.com'
    batch('Malw.link official Cloudflare Gateway', gateway, resolve(gateway)[:2])
    if time.monotonic() < END:
        batch('Bezmezhau', 'dns.bezmezhau.com', list(dict.fromkeys(['181.215.40.49', '31.58.216.201'] + resolve('dns.bezmezhau.com')))[:4])

report = dict(utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), vpnAbsence='NOT_VERIFIED',
              previousEvidence=['../transport-test3/probe.json', '../transport-test3/geohide-pool.json'],
              maxParallel=3, overallBudgetSeconds=120, ordinaryResolver='baseline/bootstrap only; never Smart DNS fallback',
              baseline=[dict(host=h, type=k, addresses=v) for (h,k),v in baseline.items()], bootstrap=bootstrap, results=results)
(OUT / 'providers.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
for row in results:
    print(row['provider'], row['ip'], row['transport']['stage'], row['transport'].get('error', ''), 'DNS rows:', len(row['dns']), 'HTTPS:', row['https'])
