-- Bounce database schema
-- Run this once in Supabase: SQL Editor → New query → paste everything → Run.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- Profiles: one row per player, created automatically when someone signs up.
-- Name and photo are copied from their Google or Apple account when available.
-- ---------------------------------------------------------------------------
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text check (char_length(display_name) <= 40),
  avatar_url text check (char_length(avatar_url) <= 500),
  suburb text check (char_length(suburb) <= 50),
  level text not null default 'All levels'
    check (level in ('All levels', 'Beginner', 'Intermediate', 'Advanced')),
  sports text[] not null default '{}',
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "Profiles are visible to everyone"
  on public.profiles for select using (true);
create policy "People create their own profile"
  on public.profiles for insert to authenticated with check (auth.uid() = id);
create policy "People edit their own profile"
  on public.profiles for update to authenticated
  using (auth.uid() = id) with check (auth.uid() = id);

create function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name, avatar_url)
  values (
    new.id,
    left(nullif(trim(coalesce(
      new.raw_user_meta_data ->> 'full_name',
      new.raw_user_meta_data ->> 'name',
      '')), ''), 40),
    left(nullif(coalesce(
      new.raw_user_meta_data ->> 'avatar_url',
      new.raw_user_meta_data ->> 'picture',
      ''), ''), 500)
  )
  on conflict do nothing;
  return new;
end $$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- Games
-- ---------------------------------------------------------------------------
create table public.games (
  id uuid primary key default gen_random_uuid(),
  host_id uuid not null references public.profiles (id) on delete cascade,
  sport text not null check (sport in (
    'pickleball', 'basketball', 'futsal', 'tennis', 'running',
    'volleyball', 'badminton', 'touch', 'padel', 'netball')),
  title text not null check (char_length(title) between 3 and 80),
  starts_at timestamptz not null,
  duration_min int not null default 90 check (duration_min between 15 and 600),
  venue text not null check (char_length(venue) between 1 and 80),
  suburb text not null check (char_length(suburb) between 1 and 50),
  level text not null default 'All levels'
    check (level in ('All levels', 'Beginner', 'Intermediate', 'Advanced')),
  price int not null default 0 check (price between 0 and 500),
  capacity int not null check (capacity between 2 and 50),
  one_short boolean not null default false,
  notes text not null default '' check (char_length(notes) <= 600),
  created_at timestamptz not null default now()
);

create index games_starts_at_idx on public.games (starts_at);

alter table public.games enable row level security;

create policy "Games are visible to everyone"
  on public.games for select using (true);
create policy "Signed-in people host games"
  on public.games for insert to authenticated with check (auth.uid() = host_id);
create policy "Hosts edit their games"
  on public.games for update to authenticated
  using (auth.uid() = host_id) with check (auth.uid() = host_id);
create policy "Hosts delete their games"
  on public.games for delete to authenticated using (auth.uid() = host_id);

-- ---------------------------------------------------------------------------
-- Who's playing in each game
-- ---------------------------------------------------------------------------
create table public.game_players (
  game_id uuid not null references public.games (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (game_id, user_id)
);

create index game_players_user_idx on public.game_players (user_id);

alter table public.game_players enable row level security;

create policy "Player lists are visible to everyone"
  on public.game_players for select using (true);
create policy "People join games themselves"
  on public.game_players for insert to authenticated with check (auth.uid() = user_id);
create policy "People leave games, hosts can remove players"
  on public.game_players for delete to authenticated using (
    auth.uid() = user_id
    or auth.uid() = (select g.host_id from public.games g where g.id = game_id)
  );

-- Stop a game from being overfilled, even if two people tap "I'm in" at once.
create function public.check_game_capacity()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  cap int;
  game_end timestamptz;
  taken int;
begin
  select capacity, starts_at + make_interval(mins => duration_min)
    into cap, game_end
    from public.games where id = new.game_id
    for update;
  if cap is null then
    raise exception 'GAME_NOT_FOUND';
  end if;
  if game_end < now() then
    raise exception 'GAME_FINISHED';
  end if;
  select count(*) into taken from public.game_players where game_id = new.game_id;
  if taken >= cap then
    raise exception 'GAME_FULL';
  end if;
  return new;
end $$;

create trigger game_players_capacity
  before insert on public.game_players
  for each row execute function public.check_game_capacity();

-- The host is always the first player in their own game.
create function public.add_host_as_player()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.game_players (game_id, user_id) values (new.id, new.host_id);
  return new;
end $$;

create trigger games_add_host
  after insert on public.games
  for each row execute function public.add_host_as_player();

-- Turn the One Short alert off automatically once a game fills.
create function public.close_one_short()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  update public.games g
     set one_short = false
   where g.id = new.game_id
     and g.one_short
     and (select count(*) from public.game_players p where p.game_id = g.id) >= g.capacity;
  return new;
end $$;

create trigger game_players_close_one_short
  after insert on public.game_players
  for each row execute function public.close_one_short();

-- ---------------------------------------------------------------------------
-- Game chat: only the host and players in a game can read or post.
-- ---------------------------------------------------------------------------
create table public.messages (
  id bigint generated always as identity primary key,
  game_id uuid not null references public.games (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  body text not null check (char_length(body) between 1 and 500),
  created_at timestamptz not null default now()
);

create index messages_game_idx on public.messages (game_id, created_at);

create function public.is_in_game(gid uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.game_players where game_id = gid and user_id = auth.uid())
      or exists (select 1 from public.games where id = gid and host_id = auth.uid());
$$;

alter table public.messages enable row level security;

create policy "Players read their game chat"
  on public.messages for select to authenticated using (public.is_in_game(game_id));
create policy "Players post in their game chat"
  on public.messages for insert to authenticated
  with check (auth.uid() = user_id and public.is_in_game(game_id));
create policy "People delete their own messages"
  on public.messages for delete to authenticated using (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- Live updates for games, players and chat
-- ---------------------------------------------------------------------------
alter publication supabase_realtime add table public.games, public.game_players, public.messages;
