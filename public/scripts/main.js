import { fetchUrlIntelligence, getScreenshotUrl } from './api-client.js';

const form = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const scanButton = document.getElementById('scanButton');
const stepLabel = document.getElementById('stepLabel');
const resultsPanel = document.getElementById('resultsPanel');
const riskValue = document.getElementById('riskValue');
const riskStatus = document.getElementById('riskStatus');
const reasonList = document.getElementById('reasonList');
const breakdownList = document.getElementById('breakdownList');
const decompositionList = document.getElementById('decompositionList');
const intelList = document.getElementById('intelList');
const screenshotImage = document.getElementById('screenshotImage');
const screenshotStatus = document.getElementById('screenshotStatus');
const historyList = document.getElementById('historyList');
const clearHistoryButton = document.getElementById('clearHistoryButton');
const themeToggle = document.getElementById('themeToggle');
const qrInput = document.getElementById('qrInput');
const qrStatus = document.getElementById('qrStatus');
const extensionNote = document.getElementById('extensionNote');

const scanSteps = [
  'Analyzing URL structure...',
  'Checking blacklist databases...',
  'Evaluating phishing patterns...',
  'Collecting domain intelligence...',
  'Preparing summary and recommendations...'
];

const suspiciousTerms = ['secure', 'login', 'verify', 'update', 'banking', 'account', 'signin', 'confirm', 'alert', 'urgent', 'password', 'credential', 'wallet', 'account', 'billing', 'reset'];
const suspectTlds = ['.xyz', '.top', '.club', '.online', '.site', '.vip', '.cc', '.tk', '.ml', '.ga', '.cf'];
const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee'];
const brandDomains = ['google.com', 'facebook.com', 'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com', 'netflix.com', 'instagram.com', 'twitter.com', 'linkedin.com'];
const homoglyphRegex = /[\u0400-\u04FF\u0500-\u052F\u2DE0-\u2DFF\uA640-\uA69F]/;
const ipRegex = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const historyKey = 'url-safety-history-v2';

let history = JSON.parse(localStorage.getItem(historyKey) || '[]');

function normalizeURL(raw) {
  if (!raw) return null;
  if (!/^https?:\/\//i.test(raw)) {
    raw = `https://${raw}`;
  }
  try {
    return new URL(raw).toString();
  } catch {
    return null;
  }
}

function getRiskCategory(score) {
  if (score >= 70) return { label: 'High Risk', class: 'high' };
  if (score >= 35) return { label: 'Moderate Risk', class: 'medium' };
  return { label: 'Safe', class: 'safe' };
}

function createReason(text, good = false) {
  return { text, good };
}

function evaluateLocalUrl(rawUrl) {
  const normalized = normalizeURL(rawUrl);
  if (!normalized) return { error: 'Invalid URL format' };

  const url = new URL(normalized);
  const hostname = url.hostname.toLowerCase();
  const path = decodeURIComponent(url.pathname || '');
  const search = url.search.toLowerCase();
  const lower = normalized.toLowerCase();
  let score = 0;
  const reasons = [];
  const indicators = new Set();
  const breakdown = {
    structure: 0,
    reputation: 0,
    impersonation: 0,
    content: 0
  };

  const subdomainParts = hostname.split('.');
  const mainDomain = subdomainParts.slice(-2).join('.');
  const subdomain = subdomainParts.slice(0, -2).join('.') || '(none)';
  const tld = '.' + subdomainParts.slice(-1)[0];

  if (hostname.includes('@')) {
    score += 22;
    reasons.push(createReason('Contains @ symbol (hides destination)'));
    breakdown.structure += 20;
    indicators.add('Redirect masking');
  }

  if (hostname.includes('-')) {
    score += 14;
    reasons.push(createReason('Hyphenated domain (common in spoofed sites)'));
    breakdown.impersonation += 12;
  }

  if (shorteners.some(short => hostname.includes(short))) {
    score += 18;
    reasons.push(createReason('URL shortener service detected'));
    breakdown.reputation += 18;
    indicators.add('Link hiding');
  }

  if (ipRegex.test(hostname)) {
    score += 30;
    reasons.push(createReason('IP address used instead of a domain name'));
    breakdown.structure += 20;
    indicators.add('Direct IP pointing');
  }

  if (suspectTlds.some(tldValue => hostname.endsWith(tldValue))) {
    score += 16;
    reasons.push(createReason(`Uses uncommon or risky TLD (${tld})`));
    breakdown.impersonation += 14;
    indicators.add('Unusual TLD');
  }

  if (path.length > 80 || search.length > 60) {
    score += 8;
    reasons.push(createReason('Long path or query string is suspicious')); 
    breakdown.content += 10;
  }

  if (lower.includes('login') || lower.includes('signin') || lower.includes('secure') || lower.includes('verify') || lower.includes('account') || lower.includes('update')) {
    score += 22;
    reasons.push(createReason('Contains phishing bait keywords')); 
    breakdown.impersonation += 18;
    indicators.add('Login bait terms');
  }

  if (homoglyphRegex.test(hostname)) {
    score += 20;
    reasons.push(createReason('Homoglyph characters found in domain')); 
    breakdown.impersonation += 20;
    indicators.add('Letter substitution');
  }

  if (hostname.replace(/\D/g, '').length > 0) {
    score += 10;
    reasons.push(createReason('Numbers in domain name may indicate spoofing')); 
    breakdown.impersonation += 10;
  }

  if (subdomainParts.length > 3) {
    score += 14;
    reasons.push(createReason('Too many subdomain levels')); 
    breakdown.structure += 12;
  }

  if (!['https:', 'http:'].includes(url.protocol)) {
    score += 20;
    reasons.push(createReason('Unsupported protocol (not HTTP/HTTPS)')); 
    breakdown.structure += 20;
  }

  if (url.protocol === 'http:') {
    score += 12;
    reasons.push(createReason('Non-secure HTTP protocol used')); 
    breakdown.reputation += 12;
  } else {
    reasons.unshift(createReason('Uses HTTPS', true));
    breakdown.reputation += 8;
  }

  if (hostname.endsWith('.gov') || hostname.endsWith('.edu')) {
    score = Math.max(score - 12, 0);
    reasons.unshift(createReason('Government or educational domain is typically more trustworthy', true));
    breakdown.reputation = Math.max(breakdown.reputation - 8, 0);
  }

  if (!hostname.includes('.') || hostname.length > 63) {
    score += 14;
    reasons.push(createReason('Domain name length or format is unusual')); 
    breakdown.structure += 12;
  }

  brandDomains.forEach(domain => {
    const brand = domain.split('.')[0];
    const typoPatterns = [brand.replace('o','0'), brand.replace('a','4'), brand.replace('e','3'), brand.replace('l','1'), brand + '1', brand + 'secure'];
    typoPatterns.forEach(variant => {
      if (hostname.includes(variant) && !hostname.includes(domain)) {
        score += 24;
        reasons.push(createReason(`Matches typosquat pattern for ${domain}`));
        breakdown.impersonation += 20;
        indicators.add('Brand impersonation');
      }
    });
  });

  const suspiciousWords = suspiciousTerms.filter(term => hostname.includes(term) || path.includes(term) || search.includes(term));
  const decomposition = {
    protocol: url.protocol.replace(':', '').toUpperCase(),
    subdomain: subdomain || '(none)',
    domain: mainDomain,
    tld,
    path: url.pathname || '/',
    query: url.search || '(none)',
    suspiciousWords: suspiciousWords.length ? suspiciousWords : ['none'],
    riskIndicators: Array.from(indicators).slice(0, 4)
  };

  const risk = Math.min(Math.max(score, 0), 100);
  const category = getRiskCategory(risk);

  return {
    url: normalized,
    risk,
    category,
    reasons,
    breakdown,
    decomposition
  };
}

function formatDate(date) {
  const diff = Date.now() - date.getTime();
  const days = Math.floor(diff / 86400000);
  if (days === 0) return 'Today';
  if (days === 1) return '1 day ago';
  return `${days} days ago`;
}

function addHistoryItem(item) {
  history = [item, ...history].slice(0, 6);
  localStorage.setItem(historyKey, JSON.stringify(history));
  renderHistory();
}

function renderHistory() {
  historyList.innerHTML = '';
  if (!history.length) {
    historyList.innerHTML = '<li class="flags-list">No recent scans yet.</li>';
    return;
  }
  history.forEach(entry => {
    const li = document.createElement('li');
    li.innerHTML = `
      <div>
        <strong>${entry.url}</strong>
        <div style="color: var(--muted); font-size:0.92rem; margin-top:0.25rem;">${entry.timestamp}</div>
      </div>
      <div class="history-status">${entry.category}</div>
    `;
    historyList.appendChild(li);
  });
}

function renderBreakdown(breakdown, categoryClass) {
  breakdownList.innerHTML = '';
  const items = [
    { label: 'Structure Risk', value: Math.min(100, breakdown.structure + 10) },
    { label: 'Domain Reputation', value: Math.min(100, breakdown.reputation + 5) },
    { label: 'Typosquat Risk', value: Math.min(100, breakdown.impersonation + 15) },
    { label: 'Content Risk', value: Math.min(100, breakdown.content + 10) }
  ];
  items.forEach(item => {
    const li = document.createElement('li');
    li.className = 'bar-line';
    li.innerHTML = `
      <span>${item.label}<strong>${item.value}%</strong></span>
      <div class="progress"><div class="progress-fill ${categoryClass}" style="width:${item.value}%"></div></div>
    `;
    breakdownList.appendChild(li);
  });
}

function renderDecomposition(data) {
  decompositionList.innerHTML = `
    <li><strong>Protocol:</strong> ${data.protocol}</li>
    <li><strong>Subdomain:</strong> ${data.subdomain}</li>
    <li><strong>Domain:</strong> ${data.domain}</li>
    <li><strong>TLD:</strong> ${data.tld}</li>
    <li><strong>Path:</strong> ${data.path}</li>
    <li><strong>Query:</strong> ${data.query}</li>
    <li><strong>Suspicious words:</strong> ${data.suspiciousWords.join(', ')}</li>
    <li><strong>Risk indicators:</strong> ${data.riskIndicators.length ? data.riskIndicators.join(', ') : 'none'}</li>
  `;
}

function renderReasons(reasons) {
  reasonList.innerHTML = '';
  reasons.forEach(reason => {
    const li = document.createElement('li');
    li.innerHTML = `<span>${reason.good ? '✅' : '❌'}</span> ${reason.text}`;
    reasonList.appendChild(li);
  });
}

function renderIntelligence(intel, categoryClass) {
  intelList.innerHTML = '';
  if (intel.error) {
    intelList.innerHTML = `<li>${intel.error}</li>`;
    return;
  }

  const safeBrowsing = intel.safeBrowsing?.available ? (intel.safeBrowsing.matches?.length ? 'Unsafe' : 'No threats detected') : 'Unavailable';
  const vtStats = intel.virusTotal?.data?.data?.attributes?.last_analysis_stats;
  const vtScore = vtStats ? `${vtStats.malicious + vtStats.suspicious} / ${Object.values(vtStats).reduce((sum, next) => sum + next, 0)}` : 'Unavailable';
  const registrar = intel.whois?.data?.WhoisRecord?.registrarName || 'Unknown';
  const createdAt = intel.whois?.data?.WhoisRecord?.createdDate ? formatDate(new Date(intel.whois.data.WhoisRecord.createdDate)) : 'Unknown';
  const abuseRisk = intel.abuseIp?.available ? `Confidence ${intel.abuseIp.data?.data?.confidence ?? 'N/A'}%` : 'Unavailable';

  const rows = [
    { label: 'Safe Browsing', value: safeBrowsing },
    { label: 'VirusTotal hits', value: vtScore },
    { label: 'Registrar', value: registrar },
    { label: 'Domain age', value: createdAt },
    { label: 'AbuseIPDB', value: abuseRisk },
    { label: 'Preview', value: 'Screenshot generated from third-party preview API' }
  ];

  rows.forEach(row => {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${row.label}:</strong> ${row.value}`;
    intelList.appendChild(li);
  });
}

function renderScreenshot(url) {
  screenshotImage.src = getScreenshotUrl(url);
  screenshotImage.alt = `Screenshot preview for ${url}`;
  screenshotStatus.textContent = 'Preview generated from live page snapshot.';
}

function setStep(index) {
  stepLabel.textContent = scanSteps[index] || 'Completing scan...';
}

function setLoading(isLoading) {
  scanButton.disabled = isLoading;
  scanButton.textContent = isLoading ? 'Scanning...' : 'Scan URL';
}

async function handleScan(event) {
  event.preventDefault();
  const rawValue = urlInput.value.trim();
  if (!rawValue) return;
  const analysis = evaluateLocalUrl(rawValue);
  if (analysis.error) {
    alert(analysis.error);
    return;
  }

  resultsPanel.classList.remove('hidden');
  setLoading(true);
  setStep(0);
  await new Promise(resolve => setTimeout(resolve, 250));
  setStep(1);
  await new Promise(resolve => setTimeout(resolve, 300));
  setStep(2);
  await new Promise(resolve => setTimeout(resolve, 300));

  const intel = await fetchUrlIntelligence(analysis.url);
  setStep(3);
  await new Promise(resolve => setTimeout(resolve, 250));
  setStep(4);

  const category = getRiskCategory(analysis.risk);
  riskValue.textContent = `${analysis.risk} / 100`;
  riskStatus.textContent = `${category.label}`;
  riskValue.className = `risk-score ${category.class}`;
  renderReasons(analysis.reasons);
  renderBreakdown(analysis.breakdown, category.class);
  renderDecomposition(analysis.decomposition);
  renderIntelligence(intel.intelligence || intel, category.class);
  renderScreenshot(analysis.url);

  addHistoryItem({
    url: analysis.url,
    category: category.label,
    timestamp: new Date().toLocaleString()
  });

  setLoading(false);
  setStep(0);
}

function handleThemeToggle() {
  document.body.classList.toggle('light-theme');
}

function decodeQrImage(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const image = new Image();
    image.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = image.naturalWidth;
      canvas.height = image.naturalHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(image, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, canvas.width, canvas.height);
      if (code?.data) {
        qrStatus.textContent = `QR code detected: ${code.data}`;
        urlInput.value = code.data;
        form.scrollIntoView({ behavior: 'smooth', block: 'center' });
        handleScan(new Event('submit'));
      } else {
        qrStatus.textContent = 'Could not detect a QR code in the image.';
      }
    };
    image.src = reader.result;
  };
  reader.readAsDataURL(file);
}

function handleQrUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  qrStatus.textContent = 'Scanning image for QR code...';
  decodeQrImage(file);
}

function renderExtensionCard() {
  extensionNote.innerHTML = `
    <p><strong>Browser extension concept:</strong> add hover scanning, live URL warnings, and pre-click protection.</p>
    <p style="color: var(--muted); margin: 0;">This website pairs well with an extension that warns users before dangerous links open.</p>
  `;
}

form.addEventListener('submit', handleScan);
clearHistoryButton.addEventListener('click', () => {
  history = [];
  localStorage.removeItem(historyKey);
  renderHistory();
});
qrInput.addEventListener('change', handleQrUpload);
themeToggle.addEventListener('click', handleThemeToggle);

renderHistory();
renderExtensionCard();
