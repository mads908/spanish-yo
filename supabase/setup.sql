-- Run once in Supabase → SQL Editor.
-- One row per account holding that person's words and progress.
create table if not exists public.progress (
  user_id uuid primary key references auth.users (id) on delete cascade,
  data jsonb not null,
  updated_at timestamptz not null default now()
);

-- Each account can only see and change its own row.
alter table public.progress enable row level security;

create policy "Read own progress" on public.progress
  for select using (auth.uid() = user_id);
create policy "Insert own progress" on public.progress
  for insert with check (auth.uid() = user_id);
create policy "Update own progress" on public.progress
  for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
