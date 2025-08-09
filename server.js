// server.js
'use strict';

const express = require('express');
const dns = require('node:dns').promises;
const path = require('node:path');

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

async function checkOneZone(ip, zone, { timeoutMs = 3000 } = {}) {
  const reversed = reverseIp(ip);
  const fqdn = `${reversed}.${zone}`;
  try {
    const A = await withTimeout(dns.resolve4(fqdn), timeoutMs, 'DNS timeout');
    let TXT = [];
    try {
      const txt = await withTimeout(dns.resolveTxt(fqdn), timeoutMs, 'DNS timeout');
      TXT = txt.flat().map(String);
    } catch (e) {
      // ignore TXT failures
    }
    return { zone, fqdn, listed: true, a: A, txt: TXT };
  } catch (err) {
    const code = err && err.code ? err.code : err.message || 'ERR';
    // ENOTFOUND/ENODATA => not listed
    if (code === 'ENOTFOUND' || code === 'ENODATA') {
      return { zone, fqdn, listed: false };
    }
    // Other errors (REFUSED/SERVFAIL/TIMEOUT etc.) are informational
    return { zone, fqdn, listed: false, error: code };
  }
}

async function checkIpAgainstDnsbls(ip, zones, { perIpConcurrency = 20, timeoutMs = 3000 } = {}) {
  const limit = createLimiter(perIpConcurrency);
  const tasks = zones.map((z) => limit(() => checkOneZone(ip, z, { timeoutMs })));
  const details = await Promise.all(tasks);
  const listedZones = details.filter(d => d.listed).map(d => d.zone);
  return {
    ip,
    listed: listedZones.length > 0,
    listedCount: listedZones.length,
    listedZones,
    details,
  };
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
    const { cidr, zones, timeoutMs = 3000, ipConcurrency = 4, perIpConcurrency = 20 } = req.body || {};
    if (!cidr || typeof cidr !== 'string') {
      return res.status(400).json({ error: 'Missing "cidr" string in body' });
    }

    const info = cidrInfo(cidr);
    const zonesToUse = Array.isArray(zones) && zones.length ? zones : DEFAULT_DNSBLS;

    const ipLimiter = createLimiter(Number(ipConcurrency) || 4);
    const tasks = info.hosts.map(ip =>
      ipLimiter(() => checkIpAgainstDnsbls(ip, zonesToUse, { perIpConcurrency, timeoutMs }))
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
