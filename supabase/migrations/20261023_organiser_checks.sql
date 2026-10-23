-- Organiser checks. People who run paid sessions or coach send their ABN, public liability insurance,
-- venue booking or council permit, coaching accreditation and Working with Children Check.
-- The Bounce Up admin looks at them and approves. Free games and games that only cover costs stay open to everyone.

-- 1. Who is checked, and until when. Public, so players see the tick; only the admin's review sets them.
alter table public.profiles add column if not exists organiser_until date;
alter table public.profiles add column if not exists coach_until date;

create or replace function private.guard_profile_checks() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if coalesce(current_setting('bounce.checks', true), '') = 'on' then return new; end if;
  if coalesce(auth.role(), '') in ('anon', 'authenticated') and not private.is_app_admin() then
    if tg_op = 'INSERT' then new.organiser_until := null; new.coach_until := null;
    else new.organiser_until := old.organiser_until; new.coach_until := old.coach_until; end if;
  end if;
  return new;
end $$;
drop trigger if exists profiles_guard_checks on public.profiles;
create trigger profiles_guard_checks before insert or update on public.profiles
  for each row execute function private.guard_profile_checks();

create or replace function private.today_vic() returns date
language sql stable set search_path = '' as $$ select (now() at time zone 'Australia/Melbourne')::date $$;

-- 2. The papers. Only the person and the admin can read them.
create table if not exists public.organiser_checks (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  wants_organiser boolean not null default false,
  wants_coach boolean not null default false,
  abn text check (abn ~ '^[0-9]{11}$'),
  abn_name text check (char_length(abn_name) <= 200),
  abn_status text check (char_length(abn_status) <= 40),
  abn_lookup boolean not null default false,
  abn_checked_at timestamptz,
  insurer text check (char_length(insurer) between 2 and 120),
  insurance_cover numeric check (insurance_cover between 0 and 1000000000),
  insurance_expires date,
  insurance_file text check (char_length(insurance_file) <= 200),
  venue_kind text check (venue_kind in ('booking', 'permit', 'club')),
  venue_name text check (char_length(venue_name) between 2 and 120),
  venue_expires date,
  venue_file text check (char_length(venue_file) <= 200),
  coach_sport text check (char_length(coach_sport) <= 30),
  coach_body text check (char_length(coach_body) between 2 and 120),
  coach_level text check (char_length(coach_level) between 2 and 120),
  coach_expires date,
  coach_file text check (char_length(coach_file) <= 200),
  wwcc_number text check (wwcc_number ~ '^[A-Za-z0-9-]{4,20}$'),
  wwcc_surname text check (char_length(wwcc_surname) between 1 and 80),
  wwcc_expires date,
  wwcc_file text check (char_length(wwcc_file) <= 200),
  organiser_status text not null default 'none' check (organiser_status in ('none', 'pending', 'approved', 'changes')),
  coach_status text not null default 'none' check (coach_status in ('none', 'pending', 'approved', 'changes')),
  organiser_hash text,
  coach_hash text,
  admin_note text check (char_length(admin_note) <= 600),
  submitted_at timestamptz,
  reviewed_at timestamptz,
  reviewed_by uuid,
  updated_at timestamptz not null default now()
);
alter table public.organiser_checks enable row level security;
revoke all on public.organiser_checks from public, anon, authenticated;
grant select on public.organiser_checks to authenticated;
drop policy if exists "People see their own checks; the admin sees all" on public.organiser_checks;
create policy "People see their own checks; the admin sees all" on public.organiser_checks for select to authenticated
  using ((select auth.uid()) = user_id or private.is_app_admin());
create index if not exists organiser_checks_review_idx on public.organiser_checks (submitted_at)
  where organiser_status = 'pending' or coach_status = 'pending';

-- 3. Private storage for the papers: PDFs and photos up to 10 MB
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('checks', 'checks', false, 10485760, array['application/pdf', 'image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;
drop policy if exists "Organisers upload their own papers" on storage.objects;
create policy "Organisers upload their own papers" on storage.objects for insert to authenticated
  with check (bucket_id = 'checks' and (storage.foldername(name))[1] = (select auth.uid())::text);
drop policy if exists "Organisers and the admin read papers" on storage.objects;
create policy "Organisers and the admin read papers" on storage.objects for select to authenticated
  using (bucket_id = 'checks' and ((storage.foldername(name))[1] = (select auth.uid())::text or private.is_app_admin()));
drop policy if exists "Organisers delete their own papers" on storage.objects;
create policy "Organisers delete their own papers" on storage.objects for delete to authenticated
  using (bucket_id = 'checks' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- 4. Save the form (and send it for checking)
create or replace function private.checks_file(p jsonb, k text, uid uuid) returns text
language plpgsql stable security definer set search_path = '' as $$
declare v text := nullif(btrim(p->>k), '');
begin
  if v is null then return null; end if;
  if split_part(v, '/', 1) <> uid::text or v !~ '^[0-9a-f-]{36}/[A-Za-z0-9._-]{1,120}$'
     or not exists (select 1 from storage.objects o where o.bucket_id = 'checks' and o.name = v) then
    raise exception 'BAD_FILE';
  end if;
  return v;
end $$;

create or replace function private.checks_date(p jsonb, k text) returns date
language plpgsql immutable set search_path = '' as $$
declare v text := nullif(btrim(p->>k), '');
begin
  if v is null then return null; end if;
  if v !~ '^\d{4}-\d{2}-\d{2}$' then raise exception 'BAD_DATE'; end if;
  return v::date;
exception when others then raise exception 'BAD_DATE';
end $$;

create or replace function private.checks_org_hash(c public.organiser_checks) returns text
language sql immutable set search_path = '' as $$
  select md5(concat_ws('|', c.abn, c.insurer, c.insurance_cover, c.insurance_expires, c.insurance_file,
    c.venue_kind, c.venue_name, c.venue_expires, c.venue_file))
$$;
create or replace function private.checks_coach_hash(c public.organiser_checks) returns text
language sql immutable set search_path = '' as $$
  select md5(concat_ws('|', c.abn, c.insurer, c.insurance_cover, c.insurance_expires, c.insurance_file,
    c.coach_sport, c.coach_body, c.coach_level, c.coach_expires, c.coach_file, c.wwcc_number, c.wwcc_surname, c.wwcc_expires, c.wwcc_file))
$$;

create or replace function public.save_organiser_checks(p jsonb, p_submit boolean default false)
returns public.organiser_checks
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := auth.uid();
  o public.organiser_checks;
  n public.organiser_checks;
  today date := private.today_vic();
  t text;
  newly boolean := false;
  admins jsonb;
  nm text;
begin
  if uid is null then raise exception 'SIGN_IN'; end if;
  if p is null or jsonb_typeof(p) <> 'object' then raise exception 'BAD_REQUEST'; end if;
  if not exists (select 1 from public.profiles where id = uid) then raise exception 'NO_PROFILE'; end if;
  insert into public.organiser_checks (user_id) values (uid) on conflict (user_id) do nothing;
  select * into o from public.organiser_checks where user_id = uid for update;
  n := o;
  n.wants_organiser := coalesce((p->>'wants_organiser')::boolean, false);
  n.wants_coach := coalesce((p->>'wants_coach')::boolean, false);
  n.insurer := left(nullif(btrim(p->>'insurer'), ''), 120);
  t := nullif(btrim(p->>'insurance_cover'), '');
  n.insurance_cover := case when t ~ '^\d{1,10}(\.\d{1,2})?$' then t::numeric when t is null then null else null end;
  n.insurance_expires := private.checks_date(p, 'insurance_expires');
  n.insurance_file := private.checks_file(p, 'insurance_file', uid);
  n.venue_kind := case when p->>'venue_kind' in ('booking', 'permit', 'club') then p->>'venue_kind' else null end;
  n.venue_name := left(nullif(btrim(p->>'venue_name'), ''), 120);
  n.venue_expires := private.checks_date(p, 'venue_expires');
  n.venue_file := private.checks_file(p, 'venue_file', uid);
  n.coach_sport := left(nullif(btrim(p->>'coach_sport'), ''), 30);
  n.coach_body := left(nullif(btrim(p->>'coach_body'), ''), 120);
  n.coach_level := left(nullif(btrim(p->>'coach_level'), ''), 120);
  n.coach_expires := private.checks_date(p, 'coach_expires');
  n.coach_file := private.checks_file(p, 'coach_file', uid);
  t := upper(nullif(regexp_replace(coalesce(p->>'wwcc_number', ''), '\s', '', 'g'), ''));
  if t is not null and t !~ '^[A-Z0-9-]{4,20}$' then raise exception 'BAD_WWCC'; end if;
  n.wwcc_number := t;
  n.wwcc_surname := left(nullif(btrim(p->>'wwcc_surname'), ''), 80);
  n.wwcc_expires := private.checks_date(p, 'wwcc_expires');
  n.wwcc_file := private.checks_file(p, 'wwcc_file', uid);

  if p_submit then
    if not (n.wants_organiser or n.wants_coach) then raise exception 'PICK_ROLE'; end if;
    if n.abn is null then raise exception 'NEEDS_ABN'; end if;
    if n.insurer is null or n.insurance_cover is null or n.insurance_expires is null or n.insurance_file is null then raise exception 'NEEDS_INSURANCE'; end if;
    if n.insurance_cover < 10000000 then raise exception 'INSURANCE_LOW'; end if;
    if n.insurance_expires <= today then raise exception 'INSURANCE_EXPIRED'; end if;
    if n.wants_organiser then
      if n.venue_kind is null or n.venue_name is null or n.venue_file is null then raise exception 'NEEDS_VENUE'; end if;
      if n.venue_expires is not null and n.venue_expires <= today then raise exception 'VENUE_EXPIRED'; end if;
    end if;
    if n.wants_coach then
      if n.coach_sport is null or n.coach_body is null or n.coach_level is null or n.coach_file is null then raise exception 'NEEDS_ACCREDITATION'; end if;
      if n.coach_expires is not null and n.coach_expires <= today then raise exception 'ACCREDITATION_EXPIRED'; end if;
      if n.wwcc_number is null or n.wwcc_surname is null or n.wwcc_expires is null then raise exception 'NEEDS_WWCC'; end if;
      if n.wwcc_expires <= today then raise exception 'WWCC_EXPIRED'; end if;
    end if;
    -- A role already approved stays approved when nothing it depends on changed
    if not n.wants_organiser then n.organiser_status := 'none'; n.organiser_hash := null;
    elsif not (o.organiser_status = 'approved' and o.organiser_hash = private.checks_org_hash(n)) then
      newly := newly or o.organiser_status <> 'pending';
      n.organiser_status := 'pending'; n.organiser_hash := private.checks_org_hash(n);
    end if;
    if not n.wants_coach then n.coach_status := 'none'; n.coach_hash := null;
    elsif not (o.coach_status = 'approved' and o.coach_hash = private.checks_coach_hash(n)) then
      newly := newly or o.coach_status <> 'pending';
      n.coach_status := 'pending'; n.coach_hash := private.checks_coach_hash(n);
    end if;
    if n.organiser_status = 'pending' or n.coach_status = 'pending' then n.admin_note := null; end if;
    n.submitted_at := now();
    -- Dropping a role ends that check
    if (not n.wants_organiser) or (not n.wants_coach) then
      perform set_config('bounce.checks', 'on', true);
      update public.profiles set
        organiser_until = case when n.wants_organiser then organiser_until else null end,
        coach_until = case when n.wants_coach then coach_until else null end
      where id = uid and ((not n.wants_organiser and organiser_until is not null) or (not n.wants_coach and coach_until is not null));
      perform set_config('bounce.checks', 'off', true);
    end if;
  end if;
  n.updated_at := now();
  update public.organiser_checks set
    wants_organiser = n.wants_organiser, wants_coach = n.wants_coach,
    insurer = n.insurer, insurance_cover = n.insurance_cover, insurance_expires = n.insurance_expires, insurance_file = n.insurance_file,
    venue_kind = n.venue_kind, venue_name = n.venue_name, venue_expires = n.venue_expires, venue_file = n.venue_file,
    coach_sport = n.coach_sport, coach_body = n.coach_body, coach_level = n.coach_level, coach_expires = n.coach_expires, coach_file = n.coach_file,
    wwcc_number = n.wwcc_number, wwcc_surname = n.wwcc_surname, wwcc_expires = n.wwcc_expires, wwcc_file = n.wwcc_file,
    organiser_status = n.organiser_status, coach_status = n.coach_status, organiser_hash = n.organiser_hash, coach_hash = n.coach_hash,
    admin_note = n.admin_note, submitted_at = n.submitted_at, updated_at = n.updated_at
  where user_id = uid
  returning * into n;

  -- Tell the admin there's something to look at (not more than once every 10 minutes per person)
  if p_submit and newly and (o.submitted_at is null or o.submitted_at < now() - interval '10 minutes') then
    select jsonb_agg(a.user_id) into admins from private.app_admins a;
    select display_name into nm from public.profiles where id = uid;
    if admins is not null then
      perform private.push_hook(jsonb_build_object('type', 'notice', 'user_ids', admins,
        'title', 'Organiser check to review',
        'body', coalesce(nm, 'Someone') || ' sent papers for ' ||
          case when n.wants_organiser and n.wants_coach then 'paid sessions and coaching' when n.wants_coach then 'coaching' else 'paid sessions' end || '.',
        'url', './#review', 'tag', 'review'));
    end if;
  end if;
  return n;
end $$;

-- 5. The admin's decision
create or replace function public.review_organiser_checks(p_user uuid, p_role text, p_action text, p_note text default null)
returns public.organiser_checks
language plpgsql security definer set search_path = '' as $$
declare
  c public.organiser_checks;
  today date := private.today_vic();
  until_d date;
  note text := left(nullif(btrim(p_note), ''), 600);
  what text := case when p_role = 'coach' then 'coaching' else 'paid sessions' end;
begin
  if not private.is_app_admin() then raise exception 'NOT_ADMIN'; end if;
  if p_role is null or p_role not in ('organiser', 'coach') or p_action is null or p_action not in ('approve', 'changes', 'revoke') then raise exception 'BAD_REQUEST'; end if;
  select * into c from public.organiser_checks where user_id = p_user for update;
  if not found then raise exception 'NO_CHECKS'; end if;
  perform set_config('bounce.checks', 'on', true);
  if p_action = 'approve' then
    if p_role = 'organiser' then
      if not c.wants_organiser or c.abn is null or c.insurance_file is null or c.insurance_expires is null or c.venue_file is null then raise exception 'INCOMPLETE'; end if;
      until_d := least(c.insurance_expires, coalesce(c.venue_expires, 'infinity'::date), today + 366);
    else
      if not c.wants_coach or c.abn is null or c.insurance_file is null or c.insurance_expires is null or c.coach_file is null or c.wwcc_expires is null then raise exception 'INCOMPLETE'; end if;
      until_d := least(c.insurance_expires, c.wwcc_expires, coalesce(c.coach_expires, 'infinity'::date), today + 366);
    end if;
    if until_d <= today then raise exception 'EXPIRED'; end if;
    if p_role = 'organiser' then
      update public.profiles set organiser_until = until_d where id = p_user;
      update public.organiser_checks set organiser_status = 'approved', admin_note = null, reviewed_at = now(), reviewed_by = auth.uid() where user_id = p_user returning * into c;
    else
      update public.profiles set coach_until = until_d where id = p_user;
      update public.organiser_checks set coach_status = 'approved', admin_note = null, reviewed_at = now(), reviewed_by = auth.uid() where user_id = p_user returning * into c;
    end if;
    perform private.push_hook(jsonb_build_object('type', 'notice', 'user_ids', jsonb_build_array(p_user),
      'title', 'You’re checked for ' || what,
      'body', case when p_role = 'coach' then 'You show in Coaches and can post clinics until ' || to_char(until_d, 'FMDD Mon YYYY') || '.'
        else 'You can post paid sessions until ' || to_char(until_d, 'FMDD Mon YYYY') || '.' end,
      'url', './#checks', 'tag', 'checks'));
  else
    if note is null then raise exception 'NOTE_REQUIRED'; end if;
    if p_action = 'revoke' then
      if p_role = 'organiser' then update public.profiles set organiser_until = null where id = p_user;
      else update public.profiles set coach_until = null where id = p_user; end if;
    end if;
    if p_role = 'organiser' then
      update public.organiser_checks set organiser_status = 'changes', admin_note = note, reviewed_at = now(), reviewed_by = auth.uid() where user_id = p_user returning * into c;
    else
      update public.organiser_checks set coach_status = 'changes', admin_note = note, reviewed_at = now(), reviewed_by = auth.uid() where user_id = p_user returning * into c;
    end if;
    perform private.push_hook(jsonb_build_object('type', 'notice', 'user_ids', jsonb_build_array(p_user),
      'title', case when p_action = 'revoke' then 'Your check for ' || what || ' was removed' else 'Your check for ' || what || ' needs a change' end,
      'body', note, 'url', './#checks', 'tag', 'checks'));
  end if;
  perform set_config('bounce.checks', 'off', true);
  return c;
end $$;

-- 6. Take my papers off Bounce Up (the app deletes the files first)
create or replace function public.delete_organiser_checks() returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid();
begin
  if uid is null then raise exception 'SIGN_IN'; end if;
  perform set_config('bounce.checks', 'on', true);
  update public.profiles set organiser_until = null, coach_until = null where id = uid;
  perform set_config('bounce.checks', 'off', true);
  delete from public.organiser_checks where user_id = uid;
end $$;

revoke all on function public.save_organiser_checks(jsonb, boolean) from public, anon;
revoke all on function public.review_organiser_checks(uuid, text, text, text) from public, anon;
revoke all on function public.delete_organiser_checks() from public, anon;
grant execute on function public.save_organiser_checks(jsonb, boolean) to authenticated;
grant execute on function public.review_organiser_checks(uuid, text, text, text) to authenticated;
grant execute on function public.delete_organiser_checks() to authenticated;
revoke all on function private.checks_file(jsonb, text, uuid) from public, anon, authenticated;

-- 7. Paid sessions need a checked organiser (or coach); clinics need a checked coach.
--    Checked means checked on the day of the game, so an expired insurance stops new paid sessions.
alter table public.games add column if not exists paid_session boolean not null default false;
create or replace function private.check_organiser() returns trigger
language plpgsql security definer set search_path = '' as $$
declare d date := (new.starts_at at time zone 'Australia/Melbourne')::date;
begin
  if new.kind = 'clinic' and (tg_op = 'INSERT' or old.kind is distinct from new.kind or old.host_id is distinct from new.host_id or old.starts_at is distinct from new.starts_at) then
    if not exists (select 1 from public.profiles p where p.id = new.host_id and p.coach_until >= d) then
      raise exception 'CLINIC_NEEDS_CHECK';
    end if;
  end if;
  if new.paid_session and new.price > 0 and (tg_op = 'INSERT' or not old.paid_session or old.price <= 0
     or old.host_id is distinct from new.host_id or old.starts_at is distinct from new.starts_at) then
    if not exists (select 1 from public.profiles p where p.id = new.host_id and (p.organiser_until >= d or p.coach_until >= d)) then
      raise exception 'PAID_NEEDS_CHECK';
    end if;
  end if;
  return new;
end $$;
drop trigger if exists games_check_organiser on public.games;
create trigger games_check_organiser before insert or update of kind, host_id, paid_session, price, starts_at on public.games
  for each row execute function private.check_organiser();

-- 8. Lessons can only be asked of a checked coach
create or replace function private.lesson_guard() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if tg_op = 'INSERT' then
    if (select count(*) from public.lesson_requests r where r.player_id = new.player_id and r.created_at > now() - interval '1 day') >= 10 then
      raise exception 'TOO_MANY_REQUESTS';
    end if;
    if not exists (select 1 from public.profiles p where p.id = new.coach_id and p.coach_until >= private.today_vic()) then
      raise exception 'COACH_NOT_CHECKED';
    end if;
  elsif new.status is distinct from old.status then
    new.replied_at := now();
  end if;
  return new;
end $$;

-- 9. Weekly sessions copy the paid-session setting (and stop if the organiser's check runs out)
create or replace function private.roll_series(p_series uuid default null::uuid)
 returns integer
 language plpgsql
 security definer
 set search_path to ''
as $function$
declare s public.game_series%rowtype; t public.games%rowtype; nxt timestamptz; newid uuid; made int := 0;
begin
  for s in select * from public.game_series gs where gs.active and (p_series is null or gs.id = p_series) for update skip locked loop
    select * into t from public.games x where x.series_id = s.id order by x.starts_at desc limit 1;
    if not found then
      update public.game_series set active = false, last_error = 'NO_GAME' where id = s.id; continue;
    end if;
    -- wait until this week's game has finished
    if s.last_starts_at + make_interval(mins => t.duration_min) > now() then continue; end if;
    if t.club_id is not null and not exists (select 1 from public.club_members m where m.club_id = t.club_id and m.user_id = t.host_id and m.role = 'admin') then
      update public.game_series set active = false, last_error = 'NOT_CLUB_ADMIN' where id = s.id; continue;
    end if;
    nxt := ((s.last_starts_at at time zone s.tz) + interval '7 days') at time zone s.tz;
    while nxt + make_interval(mins => t.duration_min) <= now() loop
      nxt := ((nxt at time zone s.tz) + interval '7 days') at time zone s.tz;
    end loop;
    begin
      insert into public.games(host_id, sport, title, starts_at, duration_min, venue, suburb, level, price, capacity, one_short, notes,
        club_id, address, lat, lng, host_plays, venue_id, kind, dupr_min, dupr_max, pay_online, pay_club, state, postcode, series_id, paid_session)
      values (t.host_id, t.sport, t.title, nxt, t.duration_min, t.venue, t.suburb, t.level, t.price, t.capacity, false, t.notes,
        t.club_id, t.address, t.lat, t.lng, t.host_plays, t.venue_id, t.kind, t.dupr_min, t.dupr_max, t.pay_online, t.pay_club, t.state, t.postcode, s.id, t.paid_session)
      returning id into newid;
      update public.game_series set last_starts_at = nxt, pending_alert_game = newid, last_error = null where id = s.id;
      made := made + 1;
    exception when others then
      -- skip this week (e.g. payouts were switched off) and tell the host on the game page
      update public.game_series set last_starts_at = nxt, last_error = left(sqlerrm, 200) where id = s.id;
    end;
  end loop;
  perform private.send_series_alerts();
  return made;
end $function$;
