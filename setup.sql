-- ============================================================
-- ROCCA AMMINISTRAZIONI — Setup Supabase
-- Eseguire nel SQL Editor di Supabase (una volta sola)
-- https://supabase.com/dashboard → progetto → SQL Editor
-- ============================================================

-- Estensione UUID
create extension if not exists "uuid-ossp";

-- ============================================================
-- TABELLE
-- ============================================================

create table if not exists profiles (
  id        uuid references auth.users(id) on delete cascade primary key,
  full_name text,
  email     text unique,
  unit      text,
  phone     text,
  role      text default 'resident',
  created_at timestamptz default now()
);

create table if not exists documents (
  id          uuid default uuid_generate_v4() primary key,
  name        text not null,
  category    text,
  file_path   text not null,
  uploaded_by uuid references profiles(id),
  created_at  timestamptz default now()
);

create table if not exists payments (
  id           uuid default uuid_generate_v4() primary key,
  resident_id  uuid references profiles(id) not null,
  description  text not null,
  amount       numeric(10,2) not null,
  due_date     date not null,
  status       text default 'pending',
  receipt_path text,
  created_at   timestamptz default now()
);

create table if not exists requests (
  id          uuid default uuid_generate_v4() primary key,
  resident_id uuid references profiles(id) not null,
  title       text not null,
  description text,
  category    text,
  status      text default 'open',
  created_at  timestamptz default now()
);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================

alter table profiles  enable row level security;
alter table documents enable row level security;
alter table payments  enable row level security;
alter table requests  enable row level security;

-- Funzione helper per evitare ricorsione RLS
create or replace function get_my_role()
returns text language sql security definer stable as $$
  select role from profiles where id = auth.uid()
$$;

-- PROFILES: tutti i condomini autenticati possono leggere i profili
create policy "profiles_select" on profiles
  for select using (auth.role() = 'authenticated');
create policy "profiles_insert" on profiles
  for insert with check (auth.uid() = id);
create policy "profiles_update" on profiles
  for update using (auth.uid() = id or get_my_role() = 'admin');

-- DOCUMENTS: tutti vedono i documenti, solo admin può caricare
create policy "documents_select" on documents
  for select using (auth.role() = 'authenticated');
create policy "documents_insert" on documents
  for insert with check (get_my_role() = 'admin');

-- PAYMENTS: condomino vede i propri, admin vede tutti
create policy "payments_select_own" on payments
  for select using (resident_id = auth.uid());
create policy "payments_select_admin" on payments
  for select using (get_my_role() = 'admin');
create policy "payments_insert_admin" on payments
  for insert with check (get_my_role() = 'admin');
create policy "payments_update_resident" on payments
  for update using (resident_id = auth.uid() and status = 'pending')
  with check (status = 'paid');
create policy "payments_update_admin" on payments
  for update using (get_my_role() = 'admin');

-- REQUESTS: condomino vede le proprie, admin vede tutte
create policy "requests_select_own" on requests
  for select using (resident_id = auth.uid());
create policy "requests_select_admin" on requests
  for select using (get_my_role() = 'admin');
create policy "requests_insert" on requests
  for insert with check (auth.role() = 'authenticated' and resident_id = auth.uid());
create policy "requests_update_admin" on requests
  for update using (get_my_role() = 'admin');

-- ============================================================
-- STORAGE POLICIES
-- (i bucket 'documenti' e 'ricevute' devono già esistere)
-- ============================================================

create policy "documenti_select" on storage.objects
  for select using (bucket_id = 'documenti' and auth.role() = 'authenticated');

create policy "documenti_insert" on storage.objects
  for insert with check (bucket_id = 'documenti' and get_my_role() = 'admin');

create policy "ricevute_insert" on storage.objects
  for insert with check (
    bucket_id = 'ricevute' and
    (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "ricevute_select_admin" on storage.objects
  for select using (
    bucket_id = 'ricevute' and get_my_role() = 'admin'
  );

create policy "ricevute_select_own" on storage.objects
  for select using (
    bucket_id = 'ricevute' and
    (storage.foldername(name))[1] = auth.uid()::text
  );

-- ============================================================
-- DOPO IL PRIMO LOGIN: assegna ruolo admin
-- Sostituire con la propria email e rieseguire
-- ============================================================
-- update profiles set role = 'admin' where email = 'pluigi.rocca@yahoo.com';
