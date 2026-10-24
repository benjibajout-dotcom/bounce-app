// Bounce Up: invite-only while the Founding Organisers get set up, before the soft launch.
// Everyone needs the access code (or an invite link with it) to open the app. It opens to everyone by itself at OPEN_AT.
// The code lives only in Cloudflare: Pages project → Settings → Variables and secrets → ACCESS_CODE (type: Secret).
// Never put the code in GitHub, email or chat. Change it there to lock out everyone who had the old one.
// Optional: OPEN_AT (a date like 2026-11-23T00:00:00+11:00, or "never") to move or cancel the automatic opening.

const OPEN_AT_DEFAULT = '2026-11-16T00:00:00+11:00';
const COOKIE = 'bu_access';
const DAYS = 90;
// Always public: link previews, icons and the legal pages
const PUBLIC = new Set(['/share.png', '/favicon.svg', '/icon-192.png', '/icon-512.png', '/apple-touch-icon.png', '/manifest.json',
  '/privacy.html', '/terms.html', '/refunds.html', '/privacy', '/terms', '/refunds']);
// Never served to anyone: behind-the-scenes files
const HIDDEN = new Set(['/schema.sql', '/bounce-app.zip', '/README.md', '/CLAUDE.md']);

const norm = (s) => String(s || '').trim().toLowerCase().replace(/\s+/g, '');
async function tokenFor(code) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('bounceup-access-v1:' + code));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function cookieOf(request) {
  const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)bu_access=([a-f0-9]{64})(?:;|$)/);
  return m ? m[1] : '';
}
function safeNext(n) {
  n = String(n || '/');
  return n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/\\') && !n.startsWith('/__access') ? n.slice(0, 2000) : '/';
}
function letIn(location, token) {
  return new Response(null, { status: 303, headers: {
    Location: location,
    'Set-Cookie': `${COOKIE}=${token}; Max-Age=${DAYS * 86400}; Path=/; Secure; HttpOnly; SameSite=Lax`,
    'Cache-Control': 'no-store',
  } });
}
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function gate(status, error, next) {
  const html = `<!doctype html><html lang="en-AU"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Bounce Up · Invite only</title><meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#173F33">
<meta property="og:title" content="Bounce Up"><meta property="og:description" content="Invite only, for now. Melbourne’s west."><meta property="og:image" content="https://bounceup.app/share.png">
<link rel="icon" href="/favicon.svg"><link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT,WONK@9..144,700..900,0..100,0..1&family=Figtree:wght@400;600;700;800&family=IBM+Plex+Mono:wght@500&family=Unbounded:wght@800&display=swap" rel="stylesheet">
<style>
:root{--bg:#F6F0DC;--ink:#13261E;--muted:#4E5D50;--forest:#173F33;--accent:#EE8436;--sun:#E9B23A;--line:#E4D9B8}
*{box-sizing:border-box}html,body{margin:0;min-height:100%}
body{min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:24px 16px;font-family:Figtree,system-ui,sans-serif;color:#F6F0DC;
background:radial-gradient(60% 40% at 50% 18%,rgba(233,178,58,.32),rgba(233,178,58,0) 70%),radial-gradient(90% 60% at 100% 110%,rgba(169,199,126,.25),transparent 60%),linear-gradient(160deg,#10291F 0%,#173F33 50%,#1F5C4A 100%)}
.card{width:100%;max-width:400px;text-align:center}
.mark{display:inline-flex;align-items:center;gap:10px;margin-bottom:34px}
.wm{font-family:Unbounded,sans-serif;font-weight:800;font-size:26px;letter-spacing:-.045em}.wm b{color:var(--accent);font-weight:800}
.seal{width:92px;height:92px;margin:0 auto 22px;border-radius:50%;display:grid;place-items:center;background:radial-gradient(circle at 35% 30%,#FFF1B8,#E9B23A 45%,#9A660A 100%);box-shadow:0 18px 40px -16px rgba(0,0,0,.6),inset 0 0 0 5px rgba(255,241,184,.35)}
.seal svg{width:44px;height:44px}
.eb{font-family:'IBM Plex Mono',monospace;font-size:12.5px;letter-spacing:.18em;text-transform:uppercase;color:#F7E0A3;margin:0 0 10px}
h1{font-family:Fraunces,Georgia,serif;font-weight:900;font-size:40px;line-height:1.02;letter-spacing:-.025em;margin:0 0 12px;text-wrap:balance;font-variation-settings:"SOFT" 100,"WONK" 1}
p.lead{margin:0 auto 26px;text-wrap:pretty;color:#C9D6C4;font-size:16.5px;line-height:1.5;max-width:30em}
form{display:flex;flex-direction:column;gap:12px;text-align:left}
label{font-size:14px;font-weight:700;color:#F6F0DC}
input{width:100%;font:600 18px Figtree,system-ui,sans-serif;letter-spacing:.06em;padding:15px 16px;border-radius:14px;border:1.5px solid rgba(246,240,220,.28);background:rgba(246,240,220,.08);color:#F6F0DC;outline:none}
input:focus{border-color:#F7E0A3;background:rgba(246,240,220,.12)}
button{font:800 17px Figtree,system-ui,sans-serif;padding:15px;border:0;border-radius:999px;background:var(--accent);color:#1A0E05;cursor:pointer}
button:focus-visible{outline:3px solid #F7E0A3;outline-offset:3px}
.err{margin:0;padding:10px 12px;border-radius:12px;background:rgba(238,132,54,.16);color:#FFD0AA;font-size:14.5px;font-weight:600}
.foot{margin:30px 0 0;font-size:14px;color:#B9C9C1;line-height:1.55}.foot a{color:#F7E0A3;font-weight:700}
</style></head><body><main class="card">
<div class="mark"><svg width="40" height="40" viewBox="0 0 100 100" aria-hidden="true"><rect width="100" height="100" rx="24" fill="#F6F0DC"/><g transform="translate(50 52) scale(0.8) translate(-50 -50)"><path d="M16 44 C 16 84, 84 84, 84 44" fill="none" stroke="#1F5C4A" stroke-width="18" stroke-linecap="round"/><circle cx="50" cy="20" r="17" fill="#EE8436"/></g></svg><span class="wm">bounce<b>up</b></span></div>
<div class="seal" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 2.8l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 16.8l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z" fill="#173F33"/></svg></div>
<p class="eb">Melbourne’s west</p><h1>Invite only, for now</h1>
<p class="lead">Our Founding Organisers are getting their games ready. Enter your access code to come in.</p>
<form method="post" action="/__access" autocomplete="off">
<label for="code">Access code</label>
<input id="code" name="code" autocapitalize="none" autocorrect="off" spellcheck="false" required autofocus enterkeyhint="go">
<input type="hidden" id="next" name="next" value="${esc(next || '/')}">
${error ? `<p class="err" role="alert">${esc(error)}</p>` : ''}
<button type="submit">Come in</button></form>
<p class="foot">Got an invite link? Open it again on this phone.<br>Run a weekly social game? <a href="mailto:benjibajout@gmail.com?subject=Founding%20Organiser%20place">Ask about a founding place</a></p>
</main><script>if(location.pathname!=='/__access'){document.getElementById('next').value=location.pathname+location.search+location.hash;}</script></body></html>`;
  return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' } });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  if (HIDDEN.has(path) || path.startsWith('/functions/')) return new Response('Not found', { status: 404, headers: { 'X-Robots-Tag': 'noindex' } });

  const code = norm(env.ACCESS_CODE);
  const openAt = Date.parse(env.OPEN_AT || OPEN_AT_DEFAULT);
  const open = Number.isFinite(openAt) && Date.now() >= openAt;
  if (code.length < 4 || open) return next(); // no code set yet, or launch day has come: everyone gets in

  if (path === '/robots.txt') return new Response('User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain' } });
  if (PUBLIC.has(path)) return next();

  const token = await tokenFor(code);
  const has = cookieOf(request) === token;

  if (path === '/__access') {
    if (request.method !== 'POST') return has ? Response.redirect(url.origin + '/', 303) : gate(401, '', '/');
    let form = null;
    try { form = await request.formData(); } catch (e) {}
    const given = norm(form && form.get('code'));
    const back = safeNext(form && form.get('next'));
    if (given && given === code) return letIn(back, token);
    await new Promise((r) => setTimeout(r, 900)); // slow down guessing
    return gate(401, 'That code didn’t work. Check it with the person who invited you.', back);
  }

  // Invite links: bounceup.app/?access=CODE (also works on any page, e.g. a game link)
  if (url.searchParams.has('access')) {
    const given = norm(url.searchParams.get('access'));
    url.searchParams.delete('access');
    const back = safeNext(url.pathname + url.search);
    if (given === code) return letIn(back, token);
    if (has) return Response.redirect(url.origin + back, 303);
    await new Promise((r) => setTimeout(r, 900));
    return gate(401, 'That invite link’s code didn’t work. Ask the person who invited you for the code.', back);
  }

  if (has) return next();
  return gate(path === '/' || path === '/index.html' ? 200 : 401, '', '/');
}
