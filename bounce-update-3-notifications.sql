-- Bounce update (20 Oct 2026, part 3): phone notifications.
create extension if not exists pg_net with schema extensions;
create extension if not exists pg_cron with schema pg_catalog;

-- What each player wants to hear about (games, oneshort, clubs, chat). Empty = everything on.
alter table public.profiles add column notify jsonb not null default '{}'::jsonb check (jsonb_typeof(notify) = 'object');
alter table public.games add column reminder_sent_at timestamptz, add column one_short_sent_at timestamptz;

-- One row per phone or browser that turned notifications on
create table public.push_subscriptions (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles (id) on delete cascade,
  endpoint text not null unique check (endpoint ~ '^https://' and char_length(endpoint) <= 1000),
  p256dh text not null check (char_length(p256dh) <= 200),
  auth text not null check (char_length(auth) <= 100),
  user_agent text check (char_length(user_agent) <= 300),
  created_at timestamptz not null default now()
);
create index push_subscriptions_user_idx on public.push_subscriptions (user_id);
alter table public.push_subscriptions enable row level security;
create policy "People see their own devices" on public.push_subscriptions for select to authenticated using ((select auth.uid()) = user_id);
create policy "People add their own devices" on public.push_subscriptions for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "People update their own devices" on public.push_subscriptions for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "People remove their own devices" on public.push_subscriptions for delete to authenticated using ((select auth.uid()) = user_id);

-- Hand an event to the "push" edge function. Never blocks or breaks the app if it fails.
create function private.push_hook(payload jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform net.http_post(
    url := 'https://kwpahyaxwgfhbnipsxdx.supabase.co/functions/v1/push',
    body := payload,
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-bounce-hook', 'aaf8c6471c75d72eb7f5974e2277e176cacd8919521a84e4'),
    timeout_milliseconds := 8000);
exception when others then
  raise warning 'push hook failed: %', sqlerrm;
end $$;

create function private.on_club_post() returns trigger language plpgsql security definer set search_path = '' as $$
begin perform private.push_hook(jsonb_build_object('type', 'club_post', 'id', new.id)); return null; end $$;
create trigger club_posts_push after insert on public.club_posts for each row execute function private.on_club_post();

create function private.on_club_message() returns trigger language plpgsql security definer set search_path = '' as $$
begin perform private.push_hook(jsonb_build_object('type', 'club_message', 'id', new.id)); return null; end $$;
create trigger club_messages_push after insert on public.club_messages for each row execute function private.on_club_message();

create function private.on_game_message() returns trigger language plpgsql security definer set search_path = '' as $$
begin perform private.push_hook(jsonb_build_object('type', 'game_message', 'id', new.id)); return null; end $$;
create trigger messages_push after insert on public.messages for each row execute function private.on_game_message();

create function private.on_one_short() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.one_short and (tg_op = 'INSERT' or not coalesce(old.one_short, false)) then
    perform private.push_hook(jsonb_build_object('type', 'one_short', 'game_id', new.id));
  end if;
  return null;
end $$;
create trigger games_one_short_push after insert or update of one_short on public.games for each row execute function private.on_one_short();

create function private.on_game_cancel() returns trigger language plpgsql security definer set search_path = '' as $$
declare ids jsonb;
begin
  if old.starts_at > now() then
    select coalesce(jsonb_agg(p.user_id), '[]'::jsonb) into ids from public.game_players p where p.game_id = old.id and p.user_id <> old.host_id;
    if jsonb_array_length(ids) > 0 then
      perform private.push_hook(jsonb_build_object('type', 'cancelled', 'game_id', old.id, 'title', old.title, 'starts_at', old.starts_at, 'user_ids', ids));
    end if;
  end if;
  return old;
end $$;
create trigger games_cancel_push before delete on public.games for each row execute function private.on_game_cancel();

-- Waitlist promotion now also tells the player
create or replace function private.fill_from_waitlist(gid uuid)
returns void language plpgsql security definer set search_path = '' as $$
declare cap int; game_end timestamptz; taken int; nxt uuid;
begin
  select g.capacity, g.starts_at + make_interval(mins => g.duration_min) into cap, game_end
    from public.games g where g.id = gid for update;
  if cap is null or game_end < now() then return; end if;
  loop
    select count(*) into taken from public.game_players p where p.game_id = gid;
    exit when taken >= cap;
    select w.user_id into nxt from public.waitlist w where w.game_id = gid order by w.created_at, w.user_id limit 1;
    exit when nxt is null;
    delete from public.waitlist w where w.game_id = gid and w.user_id = nxt;
    insert into public.game_players (game_id, user_id) values (gid, nxt) on conflict do nothing;
    perform private.push_hook(jsonb_build_object('type', 'promoted', 'game_id', gid, 'user_id', nxt));
  end loop;
end $$;

revoke execute on function private.push_hook(jsonb), private.on_club_post(), private.on_club_message(), private.on_game_message(),
  private.on_one_short(), private.on_game_cancel() from public, anon, authenticated;

-- Game reminders: every 10 minutes, remind players of games starting within 2 hours (each game once)
select cron.schedule('bounce-game-reminders', '*/10 * * * *', $$select private.push_hook('{"type":"reminders"}'::jsonb)$$);


-- Keys the notification sender reads (server only: no app user can read this table)
create table if not exists public.app_secrets (name text primary key, value text not null);
alter table public.app_secrets enable row level security;
revoke all on public.app_secrets from anon, authenticated;
insert into public.app_secrets (name, value) values
  ('vapid_public', 'BJV1kzDKc1n94uFr074Ri9scglibdD_zKSwICXYp6CVkCzBt5k0jkY8YEWrmqxOEaRfdkNjy8lfQSFIbnlKLCec'),
  ('vapid_private', '6L5F9kQx-Ife6IvKS1OrLTNfA5mr_P363hEn2eUPThU'),
  ('push_hook_secret', 'aaf8c6471c75d72eb7f5974e2277e176cacd8919521a84e4')
on conflict (name) do update set value = excluded.value;
