/**
 * Phishing Link Detector - data tables used by the scoring engine.
 *
 * Pure data, no logic. Everything is lower-case ASCII (hostnames arrive from
 * the URL parser already lower-cased and punycoded).
 */

/** Words in a domain that phishing pages use to look official. */
export const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'secure', 'verify', 'account', 'update', 'password', 'webmail',
];

/**
 * TLDs that are free or nearly free to register and show up disproportionately
 * in phishing campaigns (Spamhaus / APWG "most abused" lists).
 */
export const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'click', 'ml', 'ga', 'cf', 'gq',
  'buzz', 'icu', 'work', 'cam', 'rest', 'monster', 'zip', 'mov',
  'sbs', 'cfd', 'bond', 'lol', 'pw', 'gdn', 'surf', 'quest', 'autos', 'boats',
  'bid', 'win', 'loan', 'men', 'date', 'racing', 'faith', 'science', 'cricket',
  'accountant', 'trade', 'webcam', 'download', 'stream', 'party', 'review', 'country', 'kim',
]);

/** Registrable domains of URL shorteners: the destination cannot be judged. */
export const URL_SHORTENERS = new Set([
  'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly',
  'rebrand.ly', 'tiny.cc', 'lnkd.in', 't.ly', 'shorturl.at', 'rb.gy', 'bl.ink', 's.id',
  'v.gd', 'qr.ae', 'adf.ly', 'bit.do', 'mcaf.ee', 'fb.me', 'wp.me', 'ift.tt', 'dlvr.it',
  'trib.al', 'snip.ly', 'short.io', 'cli.gs', 'u.to', 'x.co', 'po.st', 'bc.vc', 'tr.im',
  'shorte.st', 'urlz.fr', 'v.ht', 'clck.ru', 'vk.cc', 'tinyurl.co', 'short.gy', 'zpr.io',
]);

/**
 * Large sites whose subdomains are all operated by the site itself, so a brand
 * name in a subdomain (apple.stackexchange.com) is a community, not a fake.
 * Sites that hand subdomains to users belong in PUBLIC_SUFFIXES instead.
 */
export const TRUSTED_PLATFORMS = new Set([
  'stackexchange.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'wikimedia.org',
  'fandom.com', 'quora.com', 'medium.com', 'github.com', 'gitlab.com', 'youtube.com',
  'twitter.com', 'x.com', 'facebook.com', 'instagram.com', 'linkedin.com', 'tiktok.com',
]);

/**
 * Multi-label public suffixes (subset of https://publicsuffix.org). Single-label
 * TLDs are implicit. Under any of these, the *next* label is the part someone
 * registered, so "shop.example.co.uk" -> example.co.uk and
 * "evil.github.io" -> evil.github.io.
 */
export const PUBLIC_SUFFIXES = new Set([
  // Country-code second levels
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk', 'nhs.uk', 'police.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz', 'geek.nz', 'gen.nz', 'kiwi.nz', 'maori.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'ad.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in', 'ac.in', 'edu.in', 'res.in', 'gov.in', 'nic.in',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
  'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za', 'web.za',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg', 'per.sg',
  'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk', 'idv.hk',
  'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'go.kr', 'ac.kr',
  'co.id', 'or.id', 'ac.id', 'go.id', 'my.id', 'web.id', 'sch.id', 'biz.id',
  'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my', 'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
  'co.th', 'or.th', 'ac.th', 'go.th', 'in.th', 'net.th', 'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'gen.tr', 'web.tr',
  'com.ru', 'net.ru', 'org.ru', 'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua', 'in.ua', 'kiev.ua', 'kyiv.ua',
  'com.pl', 'net.pl', 'org.pl', 'edu.pl', 'gov.pl', 'biz.pl', 'info.pl', 'waw.pl',
  'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il', 'muni.il',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar', 'com.co', 'net.co', 'org.co', 'edu.co', 'gov.co', 'nom.co',
  'com.pe', 'net.pe', 'org.pe', 'gob.pe', 'edu.pe', 'com.ve', 'net.ve', 'org.ve', 'gob.ve', 'edu.ve',
  'gob.cl', 'gov.cl', 'com.ec', 'net.ec', 'org.ec', 'gob.ec', 'edu.ec', 'com.uy', 'net.uy', 'org.uy', 'gub.uy', 'edu.uy',
  'com.pk', 'net.pk', 'org.pk', 'gov.pk', 'edu.pk', 'com.bd', 'net.bd', 'org.bd', 'gov.bd', 'edu.bd',
  'com.lk', 'net.lk', 'org.lk', 'gov.lk', 'edu.lk', 'com.np', 'net.np', 'org.np', 'gov.np', 'edu.np',
  'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg', 'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa', 'med.sa', 'sch.sa',
  'co.ae', 'net.ae', 'org.ae', 'gov.ae', 'ac.ae', 'sch.ae', 'com.ng', 'net.ng', 'org.ng', 'gov.ng', 'edu.ng', 'i.ng',
  'co.ke', 'or.ke', 'ne.ke', 'go.ke', 'ac.ke', 'me.ke', 'info.ke', 'com.gh', 'org.gh', 'gov.gh', 'edu.gh',
  'co.tz', 'or.tz', 'go.tz', 'ac.tz', 'co.ug', 'or.ug', 'go.ug', 'ac.ug', 'co.zw', 'org.zw', 'ac.zw', 'gov.zw',
  'co.ma', 'net.ma', 'org.ma', 'gov.ma', 'ac.ma', 'com.es', 'nom.es', 'org.es', 'gob.es', 'edu.es',
  'gov.it', 'edu.it', 'asso.fr', 'com.fr', 'gouv.fr', 'nom.fr', 'prd.fr', 'tm.fr',
  'ac.at', 'co.at', 'gv.at', 'or.at', 'aland.fi',
  'com.pt', 'edu.pt', 'gov.pt', 'org.pt', 'net.pt', 'nome.pt', 'publ.pt',
  'com.gr', 'edu.gr', 'net.gr', 'org.gr', 'gov.gr',
  'com.ro', 'org.ro', 'tm.ro', 'nt.ro', 'www.ro', 'firm.ro', 'nom.ro', 'info.ro', 'rec.ro', 'arts.ro', 'store.ro',
  'co.hu', 'org.hu', 'info.hu', 'priv.hu', 'sport.hu', 'tm.hu',
  'com.hr', 'from.hr', 'iz.hr', 'name.hr', 'co.rs', 'org.rs', 'edu.rs', 'ac.rs', 'gov.rs', 'in.rs',
  'gc.ca', 'on.ca', 'qc.ca', 'bc.ca', 'ab.ca', 'mb.ca', 'sk.ca', 'ns.ca', 'nb.ca', 'nl.ca',
  // Hosting, PaaS and site builders that hand out subdomains
  'github.io', 'githubusercontent.com', 'gitlab.io', 'netlify.app', 'vercel.app', 'now.sh',
  'herokuapp.com', 'herokussl.com', 'web.app', 'firebaseapp.com', 'pages.dev', 'workers.dev', 'r2.dev',
  'trycloudflare.com', 'azurewebsites.net', 'azurestaticapps.net', 'cloudapp.net', 'cloudapp.azure.com',
  'blob.core.windows.net', 'web.core.windows.net', 'azurefd.net', 'azureedge.net',
  's3.amazonaws.com', 'cloudfront.net', 'elasticbeanstalk.com', 'amplifyapp.com', 'awsapprunner.com',
  'appspot.com', 'run.app', 'blogspot.com', 'cloudfunctions.net', 'translate.goog', 'withgoogle.com',
  'wordpress.com', 'weebly.com', 'wixsite.com', 'webflow.io', 'carrd.co', 'notion.site', 'myshopify.com',
  'bigcartel.com', 'glitch.me', 'repl.co', 'replit.app', 'surge.sh', 'onrender.com', 'fly.dev',
  'railway.app', 'up.railway.app', 'koyeb.app', 'deno.dev', 'val.run', 'ngrok.io', 'ngrok-free.app',
  'ngrok.app', 'ngrok.dev', '000webhostapp.com', 'godaddysites.com', 'mystrikingly.com', 'webnode.page',
  'yolasite.com', 'jimdosite.com', 'jimdofree.com', 'hubspotpagebuilder.com', 'hubspotpagebuilder.eu',
  'dweb.link', 'w3s.link', 'ipfs.dweb.link',
  // Dynamic DNS providers (heavily used for throwaway phishing hosts)
  'duckdns.org', 'no-ip.org', 'ddns.net', 'hopto.org', 'zapto.org', 'sytes.net', 'servebeer.com',
  'myftp.org', 'dynu.net', 'dyndns.org', 'dyndns.info', 'homeip.net', 'myvnc.com', 'redirectme.net',
  'servehttp.com', 'serveminecraft.net', 'freeddns.org', 'dynv6.net',
]);

/**
 * Domains owned by the companies behind several brands each. A brand token
 * showing up under one of these (itunes.apple.com, outlook.office.com) is the
 * real thing, not impersonation.
 */
const MICROSOFT = ['microsoft', 'office', 'office365', 'live', 'msn', 'azure', 'windows', 'skype', 'bing', 'xbox', 'xboxlive', 'outlook', 'outlookmobile', 'hotmail', 'onedrive', 'sharepoint', 'sharepointonline', 'microsoftonline', 'microsoftonline-p', 'microsoftazure', 'microsoftstore', 'microsoft365', 'microsoftedge', 'microsoftstream', 'microsofttranslator', 'microsoftpersonalcontent', 'microsoftusercontent', 'msftauth', 'msauth', 'visualstudio', 'windowsazure'];
const GOOGLE = ['google', 'googleapis', 'googleusercontent', 'googlevideo', 'googleadservices', 'googlesyndication', 'googletagmanager', 'googletagservices', 'google-analytics', 'googleblog', 'googlemail', 'googlesource', 'googledrive', 'withgoogle', 'googleplex', 'googleoptimize', 'googlecode', 'googlegroups', 'googledomains', 'googlefiber', 'googlezip', 'googleweblight', 'googlecommerce', 'gmail', 'youtube', 'youtu', 'youtube-nocookie', 'youtubeeducation', 'youtubekids', 'gstatic', 'blogger', 'android', 'chromium'];
const APPLE = ['apple', 'icloud', 'itunes', 'apple-dns', 'icloud-content', 'mzstatic'];
const AMAZON = ['amazon', 'amazonaws', 'amazonpay', 'amazontrust', 'amazon-adsystem', 'amazonalexa', 'amazonmusic', 'amazonvideo', 'amazonbusiness', 'primevideo', 'audible', 'kindle'];
const META = ['facebook', 'facebookmail', 'fb', 'fbcdn', 'fbsbx', 'instagram', 'cdninstagram', 'whatsapp', 'messenger', 'meta', 'oculus', 'threads'];
const PAYPAL = ['paypal', 'paypalobjects', 'paypalcorp', 'paypalcredit', 'paypal-communication', 'paypal-prepaid', 'venmo', 'xoom'];

/**
 * Frequently impersonated brands.
 *   token  - the brand name as it appears in hostnames
 *   name   - how the tooltip refers to the brand
 *   owned  - registrable-domain labels (SLDs) belonging to the brand's company;
 *            the token itself is always implied
 */
export const BRANDS = [
  { token: 'microsoft', name: 'Microsoft', owned: MICROSOFT },
  { token: 'office365', name: 'Microsoft 365', owned: MICROSOFT },
  { token: 'outlook', name: 'Outlook', owned: MICROSOFT },
  { token: 'onedrive', name: 'OneDrive', owned: MICROSOFT },
  { token: 'sharepoint', name: 'SharePoint', owned: MICROSOFT },
  { token: 'hotmail', name: 'Hotmail', owned: MICROSOFT },
  { token: 'xbox', name: 'Xbox', owned: MICROSOFT },
  { token: 'google', name: 'Google', owned: GOOGLE },
  { token: 'gmail', name: 'Gmail', owned: GOOGLE },
  { token: 'youtube', name: 'YouTube', owned: GOOGLE },
  { token: 'apple', name: 'Apple', owned: APPLE },
  { token: 'icloud', name: 'iCloud', owned: APPLE },
  { token: 'itunes', name: 'iTunes', owned: APPLE },
  { token: 'amazon', name: 'Amazon', owned: AMAZON },
  { token: 'paypal', name: 'PayPal', owned: PAYPAL },
  { token: 'venmo', name: 'Venmo', owned: PAYPAL },
  { token: 'netflix', name: 'Netflix', owned: [] },
  { token: 'facebook', name: 'Facebook', owned: META },
  { token: 'instagram', name: 'Instagram', owned: META },
  { token: 'whatsapp', name: 'WhatsApp', owned: META },
  { token: 'linkedin', name: 'LinkedIn', owned: [] },
  { token: 'twitter', name: 'Twitter', owned: ['x', 'twimg'] },
  { token: 'tiktok', name: 'TikTok', owned: ['tiktokcdn', 'tiktokv'] },
  { token: 'telegram', name: 'Telegram', owned: ['t'] },
  { token: 'discord', name: 'Discord', owned: ['discordapp'] },
  { token: 'snapchat', name: 'Snapchat', owned: [] },
  { token: 'spotify', name: 'Spotify', owned: ['spotifycdn', 'scdn'] },
  { token: 'dropbox', name: 'Dropbox', owned: ['dropboxusercontent', 'dropboxstatic', 'dropboxapi'] },
  { token: 'docusign', name: 'DocuSign', owned: [] },
  { token: 'adobe', name: 'Adobe', owned: ['adobelogin'] },
  { token: 'github', name: 'GitHub', owned: ['githubusercontent', 'githubassets'] },
  { token: 'slack', name: 'Slack', owned: ['slack-edge', 'slack-imgs', 'slack-files', 'slack-msgs', 'slack-redir'] },
  { token: 'salesforce', name: 'Salesforce', owned: ['salesforceliveagent', 'salesforce-sites', 'salesforce-communities', 'force'] },
  { token: 'okta', name: 'Okta', owned: ['oktacdn', 'oktapreview'] },
  { token: 'intuit', name: 'Intuit', owned: ['turbotax', 'quickbooks'] },
  { token: 'turbotax', name: 'TurboTax', owned: ['intuit'] },
  { token: 'quickbooks', name: 'QuickBooks', owned: ['intuit'] },
  { token: 'shopify', name: 'Shopify', owned: ['shopifycdn'] },
  { token: 'ebay', name: 'eBay', owned: ['ebayimg', 'ebaystatic'] },
  { token: 'walmart', name: 'Walmart', owned: ['walmartimages'] },
  { token: 'costco', name: 'Costco', owned: [] },
  { token: 'bestbuy', name: 'Best Buy', owned: [] },
  { token: 'homedepot', name: 'Home Depot', owned: [] },
  { token: 'alibaba', name: 'Alibaba', owned: ['alibabagroup', 'alibabacloud', 'aliexpress', 'alicdn'] },
  { token: 'aliexpress', name: 'AliExpress', owned: ['alibaba', 'alicdn'] },
  { token: 'rakuten', name: 'Rakuten', owned: [] },
  { token: 'flipkart', name: 'Flipkart', owned: [] },
  { token: 'paytm', name: 'Paytm', owned: ['paytmmall'] },
  { token: 'phonepe', name: 'PhonePe', owned: [] },
  { token: 'coinbase', name: 'Coinbase', owned: [] },
  { token: 'binance', name: 'Binance', owned: [] },
  { token: 'metamask', name: 'MetaMask', owned: [] },
  { token: 'zelle', name: 'Zelle', owned: ['zellepay'] },
  { token: 'chase', name: 'Chase', owned: ['jpmorgan', 'jpmorganchase'] },
  { token: 'wellsfargo', name: 'Wells Fargo', owned: ['wellsfargoadvisors', 'wellsfargomedia'] },
  { token: 'bankofamerica', name: 'Bank of America', owned: ['bofa'] },
  { token: 'citibank', name: 'Citibank', owned: ['citi', 'citigroup', 'citicards', 'citidirect'] },
  { token: 'citi', name: 'Citi', owned: ['citibank', 'citigroup', 'citicards', 'citidirect'] },
  { token: 'capitalone', name: 'Capital One', owned: [] },
  { token: 'americanexpress', name: 'American Express', owned: ['amex'] },
  { token: 'amex', name: 'American Express', owned: ['americanexpress'] },
  { token: 'mastercard', name: 'Mastercard', owned: [] },
  { token: 'hsbc', name: 'HSBC', owned: [] },
  { token: 'barclays', name: 'Barclays', owned: ['barclaycard'] },
  { token: 'lloyds', name: 'Lloyds', owned: ['lloydsbank'] },
  { token: 'natwest', name: 'NatWest', owned: [] },
  { token: 'santander', name: 'Santander', owned: [] },
  { token: 'rabobank', name: 'Rabobank', owned: [] },
  { token: 'commerzbank', name: 'Commerzbank', owned: [] },
  { token: 'vodafone', name: 'Vodafone', owned: [] },
  { token: 'verizon', name: 'Verizon', owned: ['verizonwireless'] },
  { token: 'comcast', name: 'Comcast', owned: ['xfinity'] },
  { token: 'xfinity', name: 'Xfinity', owned: ['comcast'] },
  { token: 'usps', name: 'USPS', owned: [] },
  { token: 'fedex', name: 'FedEx', owned: [] },
  { token: 'dhl', name: 'DHL', owned: [] },
  { token: 'royalmail', name: 'Royal Mail', owned: [] },
  { token: 'irs', name: 'the IRS', owned: [] },
  { token: 'hmrc', name: 'HMRC', owned: [] },
  { token: 'airbnb', name: 'Airbnb', owned: [] },
  { token: 'roblox', name: 'Roblox', owned: [] },
  { token: 'steam', name: 'Steam', owned: ['steampowered', 'steamcommunity', 'steamstatic'] },
  { token: 'epicgames', name: 'Epic Games', owned: ['unrealengine'] },
  { token: 'yahoo', name: 'Yahoo', owned: ['yimg'] },
];

/**
 * Ordinary words that sit one typo away from a brand (or contain one) and must
 * not be reported as look-alikes: "finance" vs binance, "cloud" vs icloud...
 */
export const LOOKALIKE_STOPWORDS = new Set([
  'cloud', 'finance', 'papal', 'goggle', 'goole', 'twister', 'discard', 'lloyd', 'floyds',
  'citybank', 'telegrams', 'amazonas', 'amazonia', 'amazonian', 'discordant',
]);
