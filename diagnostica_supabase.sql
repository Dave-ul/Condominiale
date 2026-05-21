-- ============================================================
-- ROCCA AMMINISTRAZIONI — Diagnostica completa Supabase
-- Script di SOLA LETTURA: non modifica nulla.
-- Eseguire nel SQL Editor di Supabase e leggere la colonna "esito".
--   OK        = tutto a posto
--   ATTENZIONE = da verificare, possibile problema
--   ERRORE    = configurazione mancante, va corretta
-- ============================================================

with checks as (

  -- 1. Estensione uuid-ossp
  select 1 as ord, 'Estensioni' as categoria, 'uuid-ossp' as controllo,
    case when exists (select 1 from pg_extension where extname = 'uuid-ossp')
         then 'OK' else 'ERRORE' end as esito,
    case when exists (select 1 from pg_extension where extname = 'uuid-ossp')
         then 'installata'
         else 'manca: create extension "uuid-ossp"' end as dettaglio

  -- 2. Tabelle richieste
  union all
  select 2, 'Tabelle', t.tbl,
    case when c.relname is not null then 'OK' else 'ERRORE' end,
    case when c.relname is not null then 'presente' else 'tabella mancante' end
  from (values ('profiles'),('documents'),('payments'),('requests')) as t(tbl)
  left join pg_class c
    on c.relname = t.tbl
   and c.relkind = 'r'
   and c.relnamespace = (select oid from pg_namespace where nspname = 'public')

  -- 3. Row Level Security attiva per tabella
  union all
  select 3, 'Row Level Security', t.tbl,
    case when c.relrowsecurity then 'OK' else 'ATTENZIONE' end,
    case when c.relrowsecurity then 'RLS attiva'
         else 'RLS NON attiva: i dati sono esposti a tutti' end
  from (values ('profiles'),('documents'),('payments'),('requests')) as t(tbl)
  join pg_class c
    on c.relname = t.tbl
   and c.relnamespace = (select oid from pg_namespace where nspname = 'public')

  -- 4. Numero di policy per tabella
  union all
  select 4, 'Policy', t.tbl,
    case when count(p.policyname) > 0 then 'OK' else 'ATTENZIONE' end,
    count(p.policyname)::text || ' policy definite'
  from (values ('profiles'),('documents'),('payments'),('requests')) as t(tbl)
  left join pg_policies p on p.schemaname = 'public' and p.tablename = t.tbl
  group by t.tbl

  -- 5. Funzioni richieste: esistenza, security definer e search_path
  --    (handle_new_user DEVE avere search_path = public, altrimenti la
  --     registrazione fallisce con "relation profiles does not exist")
  union all
  select 5, 'Funzioni', f.fn,
    case
      when p.proname is null then 'ERRORE'
      when f.needs_definer and not p.prosecdef then 'ATTENZIONE'
      when f.needs_searchpath and not exists (
             select 1 from unnest(coalesce(p.proconfig, '{}')) as cfg
             where cfg like 'search_path%') then 'ATTENZIONE'
      else 'OK'
    end,
    case
      when p.proname is null then 'funzione mancante'
      else 'security_definer=' || p.prosecdef::text
           || ', search_path='
           || coalesce(
                (select split_part(cfg, '=', 2)
                   from unnest(coalesce(p.proconfig, '{}')) as cfg
                  where cfg like 'search_path%'),
                'NON impostato')
    end
  from (values
          ('get_my_role',                    true,  false),
          ('handle_new_user',                true,  true),
          ('enforce_resident_payment_update',true,  false)
       ) as f(fn, needs_definer, needs_searchpath)
  left join pg_proc p
    on p.proname = f.fn
   and p.pronamespace = (select oid from pg_namespace where nspname = 'public')

  -- 6. Trigger richiesti
  union all
  select 6, 'Trigger', tr.name,
    case when t.tgname is not null then 'OK' else 'ATTENZIONE' end,
    case when t.tgname is not null then 'presente' else 'trigger mancante' end
  from (values
          ('on_auth_user_created'),
          ('trg_enforce_resident_payment_update')
       ) as tr(name)
  left join pg_trigger t on t.tgname = tr.name and not t.tgisinternal

  -- 7. Bucket storage
  union all
  select 7, 'Storage bucket', b.name,
    case when sb.id is not null then 'OK' else 'ERRORE' end,
    case when sb.id is not null
         then 'presente (public=' || sb.public::text || ')'
         else 'bucket mancante: crearlo da Storage' end
  from (values ('documenti'),('ricevute')) as b(name)
  left join storage.buckets sb on sb.id = b.name

  -- 8. Policy sullo storage
  union all
  select 8, 'Storage policy', 'storage.objects',
    case when count(*) >= 5 then 'OK' else 'ATTENZIONE' end,
    count(*)::text || ' policy su storage.objects (attese 5)'
  from pg_policies
  where schemaname = 'storage' and tablename = 'objects'
    and policyname in ('documenti_select','documenti_insert',
                       'ricevute_insert','ricevute_select_admin','ricevute_select_own')

  -- 9. Almeno un amministratore configurato
  union all
  select 9, 'Dati', 'utenti admin',
    case when count(*) > 0 then 'OK' else 'ATTENZIONE' end,
    count(*)::text || ' utenti con role=admin'
  from public.profiles where role = 'admin'

  -- 10. Utenti registrati ma senza profilo (sintomo di trigger rotto)
  union all
  select 10, 'Dati', 'utenti senza profilo',
    case when count(*) = 0 then 'OK' else 'ATTENZIONE' end,
    count(*)::text || ' utenti auth.users senza riga in profiles'
  from auth.users u
  left join public.profiles p on p.id = u.id
  where p.id is null

  -- 11. Indici sulle foreign key più interrogate
  union all
  select 11, 'Indici', idx.name,
    case when i.indexname is not null then 'OK' else 'ATTENZIONE' end,
    case when i.indexname is not null then 'presente' else 'indice mancante (query piu lente)' end
  from (values ('idx_payments_resident_id'),('idx_requests_resident_id')) as idx(name)
  left join pg_indexes i on i.schemaname = 'public' and i.indexname = idx.name
)
select categoria, controllo, esito, dettaglio
from checks
order by ord, controllo;

-- ============================================================
-- Dettaglio policy (esegui separatamente per ispezione manuale)
-- ============================================================
-- select schemaname, tablename, policyname, cmd, qual, with_check
-- from pg_policies
-- where schemaname in ('public','storage')
-- order by tablename, policyname;
