// organiser-abn: someone who wants to run paid sessions or coach adds their ABN.
// It is checked against the Australian Business Register (ABN Lookup web services) when ABR_GUID is set;
// otherwise only the check digits are checked and the admin checks it by hand.
// Writes only the ABN fields of public.organiser_checks (needs the 20261023_organiser_checks migration).
// Deploy with verify_jwt off: it checks the signed-in user itself, like club-abn.
const SB_URL = Deno.env.get('SUPABASE_URL') ?? '';
const SERVICE = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';
const ANON = Deno.env.get('SUPABASE_ANON_KEY') ?? '';
const GUID = Deno.env.get('ABR_GUID') ?? '';
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' };
async function rest(path, init = {}) {
  const res = await fetch(`${SB_URL}/rest/v1/${path}`, { ...init, headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, 'Content-Type': 'application/json', ...(init.headers ?? {}) } });
  const text = await res.text();
  if (!res.ok) throw new Error(`db ${res.status}: ${text.slice(0, 200)}`);
  return text ? JSON.parse(text) : null;
}
async function getUser(req) {
  const auth = req.headers.get('Authorization') ?? '';
  if (!auth.startsWith('Bearer ')) return null;
  const r = await fetch(`${SB_URL}/auth/v1/user`, { headers: { Authorization: auth, apikey: ANON || SERVICE } });
  return r.ok ? r.json() : null;
}
function abnValid(abn) {
  if (!/^[0-9]{11}$/.test(abn)) return false;
  const w = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
  let sum = 0;
  for (let i = 0; i < 11; i++) sum += (Number(abn[i]) - (i === 0 ? 1 : 0)) * w[i];
  return sum % 89 === 0;
}
const clip = (v, n) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, n) : null);
async function lookup(abn) {
  const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), 8000);
  try {
    const r = await fetch(`https://abr.business.gov.au/json/AbnDetails.aspx?abn=${abn}&callback=cb&guid=${encodeURIComponent(GUID)}`, { signal: ctl.signal });
    if (!r.ok) throw new Error('ABR_DOWN');
    const t = await r.text(), i = t.indexOf('('), j = t.lastIndexOf(')');
    return JSON.parse(i >= 0 && j > i ? t.slice(i + 1, j) : t);
  } catch (_e) { throw new Error('ABR_DOWN'); }
  finally { clearTimeout(timer); }
}
async function check(user, ev) {
  const abn = String(ev.abn ?? '').replace(/[\s-]/g, '');
  if (!abnValid(abn)) throw new Error('BAD_ABN');
  const [prof] = await rest(`profiles?select=id&id=eq.${user.id}`);
  if (!prof) throw new Error('NO_PROFILE');
  const row = { user_id: user.id, abn, abn_name: null, abn_status: null, abn_lookup: false, abn_checked_at: new Date().toISOString(), updated_at: new Date().toISOString() };
  if (GUID) {
    const d = await lookup(abn);
    if (!d || !d.Abn) {
      if (/guid/i.test(String(d?.Message ?? ''))) console.log('ABN Lookup GUID problem:', String(d.Message).slice(0, 200));
      else throw new Error('ABN_NOT_FOUND');
    } else {
      if (String(d.AbnStatus) !== 'Active') throw new Error('ABN_NOT_ACTIVE');
      const names = Array.isArray(d.BusinessName) ? d.BusinessName.map((n) => (typeof n === 'string' ? n : n?.Name ?? n?.OrganisationName ?? '')).filter(Boolean) : [];
      const entity = clip(d.EntityName, 150);
      row.abn_name = clip(names[0] && entity ? `${entity} (trading as ${names[0]})` : entity || names[0], 200);
      row.abn_status = 'Active';
      row.abn_lookup = true;
    }
  }
  await rest('organiser_checks?on_conflict=user_id', { method: 'POST', headers: { Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify(row) });
  return { ok: true, abn, abn_name: row.abn_name, abn_status: row.abn_status, looked_up: row.abn_lookup };
}
const KNOWN = ['BAD_ABN', 'ABN_NOT_FOUND', 'ABN_NOT_ACTIVE', 'ABR_DOWN', 'NO_PROFILE'];
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  const reply = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...CORS, 'Content-Type': 'application/json' } });
  try {
    if (req.method !== 'POST') return reply({ ok: false }, 404);
    const ev = await req.json();
    if (ev?.action === 'status') return reply({ ok: true, lookup: !!GUID });
    const user = await getUser(req);
    if (!user?.id) return reply({ ok: false, error: 'SIGN_IN' }, 401);
    if (ev?.action === 'check') return reply(await check(user, ev));
    return reply({ ok: false, error: 'UNKNOWN' }, 400);
  } catch (e) {
    const m = String(e?.message ?? e);
    console.log('organiser-abn error', m);
    return KNOWN.includes(m) ? reply({ ok: false, error: m }) : reply({ ok: false, error: 'FAILED' }, 500);
  }
});
