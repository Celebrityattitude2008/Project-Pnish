import express from 'express';
import dotenv from 'dotenv';
import { URL } from 'url';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

const safeBrowsingKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
const virusTotalKey = process.env.VITE_VIRUSTOTAL_API_KEY;
const abuseIpDbKey = process.env.VITE_ABUSEIPDB_API_KEY;
const whoisKey = process.env.VITE_WHOIS_API_KEY;
const urlscanKey = process.env.VITE_URLSCAN_API_KEY;

function normalizeUrl(rawUrl) {
  if (!rawUrl) return null;
  if (!/^https?:\/\//i.test(rawUrl)) {
    rawUrl = `https://${rawUrl}`;
  }
  try {
    return new URL(rawUrl).toString();
  } catch {
    return null;
  }
}

async function fetchSafeBrowsing(url) {
  if (!safeBrowsingKey) return { available: false };
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safeBrowsingKey}`;
  const body = {
    client: { clientId: 'url-safety-checker', clientVersion: '1.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    return { available: true, matches: data.matches || [] };
  } catch (error) {
    return { available: true, error: error.message };
  }
}

async function fetchVirusTotal(url) {
  if (!virusTotalKey) return { available: false };
  try {
    const encoded = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
      headers: { 'x-apikey': virusTotalKey }
    });
    const data = await response.json();
    return { available: true, data };
  } catch (error) {
    return { available: true, error: error.message };
  }
}

async function fetchWhois(domain) {
  if (!whoisKey) return { available: false };
  try {
    const endpoint = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${whoisKey}&domainName=${encodeURIComponent(domain)}&outputFormat=JSON`;
    const response = await fetch(endpoint);
    const data = await response.json();
    return { available: true, data };
  } catch (error) {
    return { available: true, error: error.message };
  }
}

async function fetchAbuseIp(ip) {
  if (!abuseIpDbKey) return { available: false };
  try {
    const endpoint = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const response = await fetch(endpoint, {
      headers: { Key: abuseIpDbKey, Accept: 'application/json' }
    });
    const data = await response.json();
    return { available: true, data };
  } catch (error) {
    return { available: true, error: error.message };
  }
}

function isIpAddress(hostname) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
}

app.get('/api/intelligence', async (req, res) => {
  const rawUrl = req.query.url?.toString();
  const normalized = normalizeUrl(rawUrl);
  if (!normalized) return res.status(400).json({ error: 'Invalid URL' });

  try {
    const urlObj = new URL(normalized);
    const hostname = urlObj.hostname;
    const calls = await Promise.all([
      fetchSafeBrowsing(normalized),
      fetchVirusTotal(normalized),
      fetchWhois(hostname),
      isIpAddress(hostname) ? fetchAbuseIp(hostname) : Promise.resolve({ available: false })
    ]);

    const [safeBrowsing, virusTotal, whois, abuseIp] = calls;

    const intelligence = {
      safeBrowsing,
      virusTotal,
      whois,
      abuseIp,
      urlscanAvailable: Boolean(urlscanKey)
    };

    return res.json({ url: normalized, intelligence });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.use(express.static('public'));

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
