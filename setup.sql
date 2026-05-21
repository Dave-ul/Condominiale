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
  role      text default 'resident' check (role in ('resident', 'admin')),
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
  status       text default 'pending' check (status in ('pending', 'paid', 'verified', 'overdue')),
  receipt_path text,
  created_at   timestamptz default now()
);

create table if not exists requests (
  id          uuid default uuid_generate_v4() primary key,
  resident_id uuid references profiles(id) not null,
  title       text not null,
  description text,
  category    text,
  status      text default 'aperta' check (status in ('aperta', 'in_corso', 'chiusa')),
  created_at  timestamptz default now()
);

-- Indici sulle colonne più interrogate
create index if not exists idx_payments_resident_id on payments(resident_id);
create index if not exists idx_requests_resident_id on requests(resident_id);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================

alter table profiles  enable row level security;
alter table documents enable row level security;
alter table payments  enable row level security;
alter table requests  enable row level security;

-- Funzione helper per evitare ricorsione RLS
-- set search_path = public: necessario perché security definer non erediti
-- un search_path che non include public.
create or replace function get_my_role()
returns text language sql security definer stable set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;

-- PROFILES: tutti i condomini autenticati possono leggere i profili
drop policy if exists "profiles_select" on profiles;
create policy "profiles_select" on profiles
  for select using (auth.role() = 'authenticated');
drop policy if exists "profiles_insert" on profiles;
create policy "profiles_insert" on profiles
  for insert with check (auth.uid() = id);
drop policy if exists "profiles_update" on profiles;
create policy "profiles_update" on profiles
  for update using (auth.uid() = id or get_my_role() = 'admin');

-- DOCUMENTS: tutti vedono i documenti, solo admin può caricare
drop policy if exists "documents_select" on documents;
create policy "documents_select" on documents
  for select using (auth.role() = 'authenticated');
drop policy if exists "documents_insert" on documents;
create policy "documents_insert" on documents
  for insert with check (get_my_role() = 'admin');

-- PAYMENTS: condomino vede i propri, admin vede tutti
drop policy if exists "payments_select_own" on payments;
create policy "payments_select_own" on payments
  for select using (resident_id = auth.uid());
drop policy if exists "payments_select_admin" on payments;
create policy "payments_select_admin" on payments
  for select using (get_my_role() = 'admin');
drop policy if exists "payments_insert_admin" on payments;
create policy "payments_insert_admin" on payments
  for insert with check (get_my_role() = 'admin');
-- Il residente può solo segnare come 'paid' un pagamento 'pending' o 'overdue'.
-- Il vincolo sulle colonne modificabili è imposto dal trigger più sotto.
drop policy if exists "payments_update_resident" on payments;
create policy "payments_update_resident" on payments
  for update using (resident_id = auth.uid() and status in ('pending', 'overdue'))
  with check (resident_id = auth.uid() and status = 'paid');
drop policy if exists "payments_update_admin" on payments;
create policy "payments_update_admin" on payments
  for update using (get_my_role() = 'admin');

-- REQUESTS: condomino vede le proprie, admin vede tutte
drop policy if exists "requests_select_own" on requests;
create policy "requests_select_own" on requests
  for select using (resident_id = auth.uid());
drop policy if exists "requests_select_admin" on requests;
create policy "requests_select_admin" on requests
  for select using (get_my_role() = 'admin');
drop policy if exists "requests_insert" on requests;
create policy "requests_insert" on requests
  for insert with check (auth.role() = 'authenticated' and resident_id = auth.uid());
drop policy if exists "requests_update_admin" on requests;
create policy "requests_update_admin" on requests
  for update using (get_my_role() = 'admin');

-- ============================================================
-- TRIGGER: i residenti possono modificare SOLO status e receipt_path.
-- Impedisce a un condomino di alterare importo, descrizione, scadenza
-- o riassegnare il pagamento sfruttando la policy di update.
-- ============================================================
create or replace function enforce_resident_payment_update()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if get_my_role() = 'admin' then
    return new;
  end if;

  if new.resident_id  is distinct from old.resident_id
     or new.description is distinct from old.description
     or new.amount      is distinct from old.amount
     or new.due_date    is distinct from old.due_date
     or new.created_at  is distinct from old.created_at then
    raise exception 'I residenti possono modificare solo lo stato e la ricevuta del pagamento';
  end if;

  return new;
end;
$$;

drop trigger if exists trg_enforce_resident_payment_update on payments;
create trigger trg_enforce_resident_payment_update
  before update on payments
  for each row execute function enforce_resident_payment_update();

-- ============================================================
-- TRIGGER: creazione automatica del profilo alla registrazione.
-- set search_path = public è obbligatorio: senza, la funzione gira sotto
-- supabase_auth_admin (search_path senza public) e fallisce con
-- "relation profiles does not exist" → "Database error saving new user".
-- ============================================================
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, full_name, email, unit, phone, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', new.email),
    new.email,
    coalesce(new.raw_user_meta_data->>'unit', ''),
    coalesce(new.raw_user_meta_data->>'phone', ''),
    'resident'
  )
  on conflict (id) do nothing;
  return new;
exception
  when others then
    return new;  -- non bloccare mai la registrazione se la creazione profilo fallisce
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ============================================================
-- TRIGGER: impedisce a un residente di promuoversi ad admin.
-- La policy profiles_update consente di aggiornare la propria riga,
-- ma le RLS non sanno limitare le colonne: questo trigger blocca le
-- modifiche al campo role da parte dei non-admin.
-- ============================================================
create or replace function public.enforce_profile_update()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if get_my_role() = 'admin' then
    return new;
  end if;
  if new.role is distinct from old.role then
    raise exception 'Non puoi modificare il tuo ruolo';
  end if;
  return new;
end;
$$;

drop trigger if exists trg_enforce_profile_update on profiles;
create trigger trg_enforce_profile_update
  before update on profiles
  for each row execute function public.enforce_profile_update();

-- ============================================================
-- STORAGE POLICIES
-- (i bucket 'documenti' e 'ricevute' devono già esistere)
-- ============================================================

drop policy if exists "documenti_select" on storage.objects;
create policy "documenti_select" on storage.objects
  for select using (bucket_id = 'documenti' and auth.role() = 'authenticated');

drop policy if exists "documenti_insert" on storage.objects;
create policy "documenti_insert" on storage.objects
  for insert with check (bucket_id = 'documenti' and get_my_role() = 'admin');

drop policy if exists "ricevute_insert" on storage.objects;
create policy "ricevute_insert" on storage.objects
  for insert with check (
    bucket_id = 'ricevute' and
    (storage.foldername(name))[1] = auth.uid()::text
  );

drop policy if exists "ricevute_select_admin" on storage.objects;
create policy "ricevute_select_admin" on storage.objects
  for select using (
    bucket_id = 'ricevute' and get_my_role() = 'admin'
  );

drop policy if exists "ricevute_select_own" on storage.objects;
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
