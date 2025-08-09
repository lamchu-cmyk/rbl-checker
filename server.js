// server.js
'use strict';

const express = require('express');
const dns = require('node:dns').promises;
const path = require('node:path');
const { Resolver } = require('node:dns').promises;
const https = require('node:https');

const DEFAULT_NAMESERVERS = (process.env.NAMESERVERS || '1.1.1.1,8.8.8.8,9.9.9.9')
  .split(/\s*,\s*/).filter(Boolean);

function buildResolvers(nameservers) {
  const list = (Array.isArray(nameservers) ? nameservers
               : String(nameservers || '').split(','))
               .map(s => s.trim()).filter(Boolean);
  const servers = list.length ? list : DEFAULT_NAMESERVERS;
  return servers.map(ns => {
    const r = new Resolver();
    r.setServers([ns]);
    return r;
  });
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function resolveWithResolvers(resolvers, fqdn, type, timeoutMs) {
  let lastErr;
  for (const r of resolvers) {
    try {
      if (type === 'A') return await withTimeout(r.resolve4(fqdn, { ttl: true }), timeoutMs, 'DNS timeout');
      return await withTimeout(r.resolveTxt(fqdn), timeoutMs, 'DNS timeout');
    } catch (e) {
      lastErr = e;
      const code = e && e.code ? e.code : e.message || 'ERR';
      if (code === 'ENOTFOUND' || code === 'ENODATA') throw e; // không cần thử tiếp
      // các lỗi khác (TIMEOUT/SERVFAIL/REFUSED) → thử resolver tiếp theo
    }
  }
  // Fallback DoH: Cloudflare → Google
  try {
    return await resolveViaDoh('cloudflare', fqdn, type, timeoutMs);
  } catch (e1) {
    lastErr = e1;
  }
  try {
    return await resolveViaDoh('google', fqdn, type, timeoutMs);
  } catch (e2) {
    lastErr = e2;
  }
  throw lastErr;
}

function httpGetJson(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: 'GET', headers }, (res) => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (d) => (buf += d));
      res.on('end', () => {
        try { resolve(JSON.parse(buf)); } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function resolveViaDoh(provider, fqdn, type, timeoutMs) {
  const enc = encodeURIComponent;
  const url = provider === 'cloudflare'
    ? `https://cloudflare-dns.com/dns-query?name=${enc(fqdn)}&type=${enc(type)}`
    : `https://dns.google/resolve?name=${enc(fqdn)}&type=${enc(type)}`;

  const headers = provider === 'cloudflare' ? { accept: 'application/dns-json' } : {};
  const json = await withTimeout(httpGetJson(url, headers), timeoutMs, 'DNS timeout');

  // Status 0 = NOERROR; 3 = NXDOMAIN; 2 = SERVFAIL; 5 = REFUSED
  if (json.Status === 0 && Array.isArray(json.Answer)) {
    if (type === 'A') {
      return json.Answer
        .filter(a => a.type === 1 && typeof a.data === 'string')
        .map(a => ({ address: a.data, ttl: a.TTL }));
    } else if (type === 'TXT') {
      const txts = json.Answer
        .filter(a => a.type === 16 && typeof a.data === 'string')
        .map(a => a.data.replace(/^"|"$/g, ''));
      // match Node's shape: string[][]
      return txts.map(s => [s]);
    }
  }
  const map = { 3: 'ENOTFOUND', 2: 'SERVFAIL', 5: 'REFUSED' };
  const err = new Error(map[json.Status] || `DOH_STATUS_${json.Status}`);
  err.code = map[json.Status] || `DOH_STATUS_${json.Status}`;
  throw err;
}

const app = express();
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const PORT = process.env.PORT || 3000;

// A reasonable default DNSBL set (you can add/remove)
const DEFAULT_DNSBLS = [
  // Spamhaus family
  'zen.spamhaus.org', 'sbl.spamhaus.org', 'xbl.spamhaus.org', 'pbl.spamhaus.org',
  // Spamcop
  'bl.spamcop.net',
  // SORBS family
  'dnsbl.sorbs.net', 'socks.dnsbl.sorbs.net', 'http.dnsbl.sorbs.net', 'smtp.dnsbl.sorbs.net',
  'misc.dnsbl.sorbs.net', 'web.dnsbl.sorbs.net', 'dul.dnsbl.sorbs.net', 'zombie.dnsbl.sorbs.net',
  'spam.dnsbl.sorbs.net',
  // UCEPROTECT
  'dnsbl-1.uceprotect.net', 'dnsbl-2.uceprotect.net', 'dnsbl-3.uceprotect.net',
  // Others commonly referenced
  'b.barracudacentral.org', // requires registration; may return REFUSED/SERVFAIL
  'psbl.surriel.com',
  'cbl.abuseat.org',
  'combined.abuse.ch', 'spam.abuse.ch', 'drone.abuse.ch',
  'dnsbl.dronebl.org',
  'db.wpbl.info',
  'cdl.anti-spam.org.cn',
  'blacklist.woody.ch',
  'ips.backscatterer.org',
  'korea.services.net',
  'short.rbl.jp', 'virus.rbl.jp',
  'ubl.lashback.com',
  'ubl.unsubscore.com',
  'relays.bl.gweep.ca', 'proxy.bl.gweep.ca',
  'wormrbl.imp.ch',
  'spam.spamrats.com', 'dyna.spamrats.com',
  'spambot.bls.digibase.ca',
  'z.mailspike.net',
  'all.s5h.net',
];

// ---------- IPv4 + CIDR helpers ----------
function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => /^\d+$/.test(p) && +p >= 0 && +p <= 255);
}

function parseCidr(cidr) {
  if (typeof cidr !== 'string') throw new Error('CIDR must be string');
  const [ip, prefixStr] = cidr.trim().split('/');
  const prefix = Number(prefixStr);
  if (!isValidIPv4(ip)) throw new Error('Invalid IPv4 address');
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new Error('Invalid prefix length');
  return { ip, prefix };
}

function ipToLong(ip) {
  const [a, b, c, d] = ip.split('.').map(Number);
  return (((a << 24) >>> 0) + (b << 16) + (c << 8) + d) >>> 0;
}

function longToIp(n) {
  return [
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255,
  ].join('.');
}

function cidrInfo(cidr) {
  const { ip, prefix } = parseCidr(cidr);
  const ipLong = ipToLong(ip);
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const network = (ipLong & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;

  const networkIp = longToIp(network);
  const broadcastIp = longToIp(broadcast);

  // Usable hosts exclude network and broadcast (except for /31, /32 which have no usable)
  let firstHost = network + 1;
  let lastHost = broadcast - 1;
  if (prefix >= 31) {
    firstHost = 1; // sentinel, will produce an empty list
    lastHost = 0;
  }

  const hosts = [];
  for (let n = firstHost; n <= lastHost; n++) hosts.push(longToIp(n));

  return {
    input: cidr,
    normalizedCidr: `${networkIp}/${prefix}`,
    network: networkIp,
    broadcast: broadcastIp,
    prefix,
    hosts,
  };
}

// ---------- Concurrency + Timeout helpers ----------
function createLimiter(limit) {
  let active = 0;
  const queue = [];
  const next = () => {
    while (active < limit && queue.length) {
      active++;
      const { task, resolve, reject } = queue.shift();
      task()
        .then(resolve, reject)
        .finally(() => {
          active--;
          next();
        });
    }
  };
  return (task) =>
    new Promise((resolve, reject) => {
      queue.push({ task, resolve, reject });
      next();
    });
}

function withTimeout(promise, ms, label = 'timeout') {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(label)), ms)),
  ]);
}

// ---------- DNSBL checking ----------
function reverseIp(ip) {
  return ip.split('.').reverse().join('.');
}

async function checkOneZone(ip, zone, { resolvers, timeoutMs = 5000, jitterMs = 200 } = {}) {
  const reversed = reverseIp(ip);
  const fqdn = `${reversed}.${zone}`;
  const t0 = Date.now();

  const parseA = (A) => {
    let addresses = [];
    let ttl;
    if (Array.isArray(A) && A.length) {
      if (typeof A[0] === 'object' && A[0] && 'address' in A[0]) {
        addresses = A.map(r => r.address);
        const ttls = A.map(r => r.ttl).filter(v => Number.isFinite(v));
        if (ttls.length) ttl = Math.min(...ttls);
      } else {
        addresses = A;
      }
    }
    return { addresses, ttl };
  };

  if (jitterMs) await sleep(Math.random() * jitterMs);

  try {
    const Araw = await resolveWithResolvers(resolvers, fqdn, 'A', timeoutMs);
    const { addresses, ttl } = parseA(Araw);

    let TXT = [];
    try {
      const txt = await resolveWithResolvers(resolvers, fqdn, 'TXT', timeoutMs);
      TXT = txt.flat().map(String);
    } catch { /* ignore TXT failures */ }

    return { zone, fqdn, listed: true, a: addresses, txt: TXT, ttl, ms: Date.now() - t0 };
  } catch (err) {
    const code = err && err.code ? err.code : err.message || 'ERR';
    const ms = Date.now() - t0;
    if (code === 'ENOTFOUND' || code === 'ENODATA') {
      return { zone, fqdn, listed: false, ms };
    }
    return { zone, fqdn, listed: false, error: code, ms };
  }
}

async function checkIpAgainstDnsbls(ip, zones, opts = {}) {
  const { perIpConcurrency = 8, timeoutMs = 5000, resolvers } = opts;
  const limit = createLimiter(perIpConcurrency);
  const tasks = zones.map(z => limit(() => checkOneZone(ip, z, { timeoutMs, resolvers })));
  const details = await Promise.all(tasks);
  const listedZones = details.filter(d => d.listed).map(d => d.zone);
  return { ip, listed: listedZones.length > 0, listedCount: listedZones.length, listedZones, details };
}

// ---------- Routes ----------
app.get('/', (_req, res) => {
  res.render('index');
});

app.get('/blacklists', (_req, res) => {
  res.json({ zones: DEFAULT_DNSBLS });
});

// POST /check { cidr, zones?, timeoutMs?, ipConcurrency?, perIpConcurrency? }
app.post('/check', async (req, res) => {
  try {
    const {
      cidr,
      zones,
      timeoutMs = 5000,
      ipConcurrency = 2,
      perIpConcurrency = 8,
      nameservers
    } = req.body || {};
    if (!cidr || typeof cidr !== 'string') {
      return res.status(400).json({ error: 'Missing "cidr" string in body' });
    }

    const info = cidrInfo(cidr);
    const zonesToUse = Array.isArray(zones) && zones.length ? zones : DEFAULT_DNSBLS;
    const resolvers = buildResolvers(nameservers);

    const ipLimiter = createLimiter(Number(ipConcurrency) || 2);
    const tasks = info.hosts.map(ip =>
      ipLimiter(() => checkIpAgainstDnsbls(ip, zonesToUse, { perIpConcurrency, timeoutMs, resolvers }))
    );
    const results = await Promise.all(tasks);

    res.json({
      input: cidr,
      normalizedCidr: info.normalizedCidr,
      network: info.network,
      broadcast: info.broadcast,
      prefix: info.prefix,
      usableHosts: info.hosts,
      usableHostCount: info.hosts.length,
      zonesChecked: zonesToUse.length,
      timeoutMs,
      nameservers: (Array.isArray(nameservers) ? nameservers : String(nameservers || '')).split(',').map(s => s.trim()).filter(Boolean),
      results,
      generatedAt: new Date().toISOString(),
    });
  } catch (e) {
    res.status(400).json({ error: e.message || String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`RBL checker listening on http://localhost:${PORT}`);
});
