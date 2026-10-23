-- For Gael: apply after 20261023_organiser_checks.sql. Tested on a local copy of the schema
-- (reports insert/RLS/limit/admin review; delete_my_account blockers, club hand-over, payments kept).
-- The live app already checks for these and switches over by itself once they exist:
--   * reports table  -> in-app reports + the admin's Reports list (#reports)
--   * delete_my_account(dry_run) -> Profile > Delete my account works in-app (until then it emails Ben)
-- If Supabase refuses "delete from auth.users" inside the function, keep the function but drop that
-- line, and delete the user from an edge function with auth.admin.deleteUser(uid) after it returns ok.

-- Safety: in-app reports, and people deleting their own account.
-- The app already works without this (reports go by email, delete-account requests go by email).
-- Once this is applied, the app finds it by itself and switches to the in-app versions.

-- 1. Reports. Anyone signed in can report a person, game, club or post. Only the app admin reads them.
create table if not exists public.reports (
  id bigint generated always as identity primary key,
  reporter_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  kind text not null check (kind in ('person', 'game', 'club', 'post')),
  target_id text not null check (char_length(target_id) between 1 and 80),
  target_user uuid references public.profiles(id) on delete set null,
  target_label text check (char_length(target_label) <= 120),
  reason text not null check (reason in ('harassment', 'hate', 'sexual', 'scam', 'unsafe', 'underage', 'other')),
  details text check (char_length(details) <= 1000),
  status text not null default 'open' check (status in ('open', 'actioned', 'dismissed')),
  admin_note text check (char_length(admin_note) <= 500),
  handled_by uuid references public.profiles(id) on delete set null,
  handled_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists reports_open_idx on public.reports (created_at desc) where status = 'open';
create index if not exists reports_reporter_idx on public.reports (reporter_id, created_at desc);
alter table public.reports enable row level security;

drop policy if exists "Signed-in people send reports" on public.reports;
create policy "Signed-in people send reports" on public.reports for insert to authenticated
  with check ((select auth.uid()) = reporter_id and status = 'open' and admin_note is null and handled_by is null and handled_at is null);
drop policy if exists "Reporters and the admin see reports" on public.reports;
create policy "Reporters and the admin see reports" on public.reports for select to authenticated
  using ((select auth.uid()) = reporter_id or private.is_app_admin());
grant select, insert on public.reports to authenticated;

-- At most 20 reports a day from one person, so it can't be used to flood the admin.
create or replace function private.report_limit() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if (select count(*) from public.reports where reporter_id = new.reporter_id and created_at > now() - interval '1 day') >= 20 then
    raise exception 'REPORT_LIMIT';
  end if;
  return new;
end $$;
drop trigger if exists reports_limit on public.reports;
create trigger reports_limit before insert on public.reports for each row execute function private.report_limit();

-- The admin marks a report as dealt with ('actioned') or not needing action ('dismissed').
create or replace function public.review_report(report_id bigint, new_status text, note text default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not private.is_app_admin() then raise exception 'NOT_ADMIN'; end if;
  if new_status not in ('open', 'actioned', 'dismissed') then raise exception 'BAD_STATUS'; end if;
  update public.reports
     set status = new_status, admin_note = left(note, 500),
         handled_by = case when new_status = 'open' then null else auth.uid() end,
         handled_at = case when new_status = 'open' then null else now() end
   where id = report_id;
end $$;
revoke all on function public.review_report(bigint, text, text) from public, anon;
grant execute on function public.review_report(bigint, text, text) to authenticated;

-- 2. Delete my account.
-- Payment records stay for 5 years (tax law), without the person's account attached.
alter table public.payments alter column user_id drop not null;
alter table public.payments drop constraint if exists payments_user_id_fkey;
alter table public.payments add constraint payments_user_id_fkey
  foreign key (user_id) references public.profiles(id) on delete set null;

-- dry_run = true only lists what stops the deletion; nothing changes.
-- Returns {"ok": true} or {"ok": false, "blockers": [{"kind": ..., "id": ..., "name": ...}]}.
-- Blockers: upcoming games they host that other people joined, upcoming games they paid for
-- (leave first to get the refund), clubs where they're the only committee member but others belong,
-- and leagues without a club that they run while other people are entered.
create or replace function public.delete_my_account(dry_run boolean default false)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  me uuid := auth.uid();
  blockers jsonb := '[]'::jsonb;
  r record;
begin
  if me is null then raise exception 'NOT_SIGNED_IN'; end if;

  for r in select g.id, g.title from public.games g
            where g.host_id = me and g.starts_at + make_interval(mins => g.duration_min) > now()
              and exists (select 1 from public.game_players gp where gp.game_id = g.id and gp.user_id <> me)
  loop blockers := blockers || jsonb_build_object('kind', 'hosting', 'id', r.id, 'name', r.title); end loop;

  for r in select distinct g.id, g.title from public.payments p join public.games g on g.id = p.game_id
            where p.user_id = me and p.status = 'paid' and g.host_id <> me
              and g.starts_at + make_interval(mins => g.duration_min) > now()
  loop blockers := blockers || jsonb_build_object('kind', 'paid', 'id', r.id, 'name', r.title); end loop;

  for r in select c.id, c.name from public.clubs c join public.club_members m on m.club_id = c.id and m.user_id = me and m.role = 'admin'
            where not exists (select 1 from public.club_members o where o.club_id = c.id and o.role = 'admin' and o.user_id <> me)
              and exists (select 1 from public.club_members o where o.club_id = c.id and o.user_id <> me)
  loop blockers := blockers || jsonb_build_object('kind', 'club', 'id', r.id, 'name', r.name); end loop;

  for r in select l.id, l.name from public.leagues l
            where l.created_by = me and l.club_id is null and l.status <> 'finished'
              and exists (select 1 from public.league_entries e where e.league_id = l.id and e.captain_id <> me)
  loop blockers := blockers || jsonb_build_object('kind', 'league', 'id', r.id, 'name', r.name); end loop;

  if jsonb_array_length(blockers) > 0 then return jsonb_build_object('ok', false, 'blockers', blockers); end if;
  if dry_run then return jsonb_build_object('ok', true); end if;

  -- Clubs they started that other committee members keep running: hand them over, so the club stays.
  update public.clubs c set created_by = (
      select m.user_id from public.club_members m where m.club_id = c.id and m.role = 'admin' and m.user_id <> me
      order by m.joined_at limit 1)
   where c.created_by = me
     and exists (select 1 from public.club_members m where m.club_id = c.id and m.role = 'admin' and m.user_id <> me);
  -- Club leagues they set up stay with the club's committee.
  update public.leagues l set created_by = (
      select m.user_id from public.club_members m where m.club_id = l.club_id and m.role = 'admin' and m.user_id <> me
      order by m.joined_at limit 1)
   where l.created_by = me and l.club_id is not null
     and exists (select 1 from public.club_members m where m.club_id = l.club_id and m.role = 'admin' and m.user_id <> me);
  -- Clubs where they're the only person left close with them.
  delete from public.clubs c
   where exists (select 1 from public.club_members m where m.club_id = c.id and m.user_id = me)
     and not exists (select 1 from public.club_members o where o.club_id = c.id and o.user_id <> me);

  -- Everything else goes with the account through the existing "on delete cascade" links:
  -- profile, messages, comments, likes, club memberships, game spots, waitlists, coach listing,
  -- lesson requests, payout account record, organiser checks, push subscriptions, past games they hosted.
  -- Their photos and check files are removed by the app (Storage API) before it calls this.
  delete from auth.users where id = me;
  return jsonb_build_object('ok', true);
end $$;
revoke all on function public.delete_my_account(boolean) from public, anon;
grant execute on function public.delete_my_account(boolean) to authenticated;
