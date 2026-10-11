-- مخزني: جداول مساندة لميزات الجرد اليومي والتذكيرات والمناديب والمتجر.
-- راجع الملف ثم شغّله مرة واحدة في Supabase SQL Editor.

alter table public.products
  add column if not exists purchase_price numeric(12,3) not null default 0 check (purchase_price >= 0),
  add column if not exists sale_price numeric(12,3) not null default 0 check (sale_price >= 0),
  add column if not exists sales_rep_phone text,
  add column if not exists store_visible boolean not null default false,
  add column if not exists category text not null default 'أخرى';

alter table public.shops
  add column if not exists store_slug text,
  add column if not exists store_enabled boolean not null default false;

create unique index if not exists shops_store_slug_unique
  on public.shops (store_slug) where store_slug is not null;

create table if not exists public.sales_reps (
  id uuid primary key default gen_random_uuid(),
  shop_id uuid not null references public.shops(id) on delete cascade,
  name text not null,
  phone text not null,
  notes text,
  created_at timestamptz not null default now(),
  unique (shop_id, phone)
);

create table if not exists public.reminders (
  id uuid primary key default gen_random_uuid(),
  shop_id uuid not null references public.shops(id) on delete cascade,
  title text not null,
  details text,
  due_at timestamptz,
  is_done boolean not null default false,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.daily_sessions (
  id uuid primary key default gen_random_uuid(),
  shop_id uuid not null references public.shops(id) on delete cascade,
  work_date date not null default current_date,
  opening_cash numeric(12,3) not null default 0 check (opening_cash >= 0),
  notes text,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (shop_id, work_date)
);

create table if not exists public.daily_stock_counts (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null references public.daily_sessions(id) on delete cascade,
  product_id uuid not null references public.products(id) on delete cascade,
  expected_quantity integer not null default 0 check (expected_quantity >= 0),
  counted_quantity integer not null check (counted_quantity >= 0),
  counted_at timestamptz not null default now(),
  unique (session_id, product_id)
);

alter table public.sales_reps enable row level security;
alter table public.reminders enable row level security;
alter table public.daily_sessions enable row level security;
alter table public.daily_stock_counts enable row level security;

grant select, insert, update, delete on public.sales_reps, public.reminders, public.daily_sessions, public.daily_stock_counts to authenticated;

drop policy if exists sales_reps_member_access on public.sales_reps;
create policy sales_reps_member_access on public.sales_reps for all to authenticated
using (public.is_shop_member(shop_id)) with check (public.is_shop_member(shop_id));

drop policy if exists reminders_member_access on public.reminders;
create policy reminders_member_access on public.reminders for all to authenticated
using (public.is_shop_member(shop_id)) with check (public.is_shop_member(shop_id));

drop policy if exists daily_sessions_member_access on public.daily_sessions;
create policy daily_sessions_member_access on public.daily_sessions for all to authenticated
using (public.is_shop_member(shop_id)) with check (public.is_shop_member(shop_id));

drop policy if exists daily_stock_counts_member_access on public.daily_stock_counts;
create policy daily_stock_counts_member_access on public.daily_stock_counts for all to authenticated
using (exists (select 1 from public.daily_sessions ds where ds.id = session_id and public.is_shop_member(ds.shop_id)))
with check (exists (select 1 from public.daily_sessions ds where ds.id = session_id and public.is_shop_member(ds.shop_id)));


-- واجهة المتجر العامة تستخدم RPC آمنًا ولا تمنح الزوار قراءة جدول المخزون مباشرة.
revoke select on public.shops, public.products from anon;
drop policy if exists shops_public_enabled_store on public.shops;
drop policy if exists products_public_store_catalog on public.products;

create or replace function public.get_public_store(p_slug text)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select jsonb_build_object(
    'shop_name', s.name,
    'products', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', p.id,
        'name', p.name,
        'category', coalesce(p.category, 'أخرى'),
        'sale_price', p.sale_price,
        'in_stock', (p.quantity > 0)
      ) order by p.created_at desc)
      from public.products p
      where p.shop_id = s.id and p.store_visible = true
    ), '[]'::jsonb)
  )
  from public.shops s
  where s.store_slug = p_slug and s.store_enabled = true
  limit 1;
$$;
revoke all on function public.get_public_store(text) from public;
grant execute on function public.get_public_store(text) to anon, authenticated;

-- أدوات إدارة أعضاء المحل: لا يمكن إلا لمسؤول المحل تنفيذها.
create or replace function public.admin_list_shop_members(p_shop_id uuid)
returns table(user_id uuid, role text, created_at timestamptz, email text)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_shop_admin(p_shop_id) then
    raise exception 'Admin role required';
  end if;
  return query
    select sm.user_id, sm.role, sm.created_at, au.email::text
    from public.shop_members sm
    join auth.users au on au.id = sm.user_id
    where sm.shop_id = p_shop_id
    order by sm.created_at;
end;
$$;

create or replace function public.admin_add_shop_member_by_email(p_shop_id uuid, p_email text, p_role text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare target_user_id uuid;
begin
  if not public.is_shop_admin(p_shop_id) then
    raise exception 'Admin role required';
  end if;
  if p_role not in ('Admin', 'Coordinator', 'Staff') then
    raise exception 'Invalid role';
  end if;
  select id into target_user_id from auth.users where lower(email) = lower(trim(p_email)) limit 1;
  if target_user_id is null then
    raise exception 'No registered account found for this email';
  end if;
  -- Prevent demoting the only Admin to a non-Admin role.
  if p_role <> 'Admin' and exists (
    select 1
    from public.shop_members sm
    where sm.shop_id = p_shop_id
      and sm.user_id = target_user_id
      and sm.role = 'Admin'
      and (select count(*) from public.shop_members sm2
           where sm2.shop_id = p_shop_id and sm2.role = 'Admin') <= 1
  ) then
    raise exception 'Cannot demote the last Admin';
  end if;
  insert into public.shop_members(shop_id, user_id, role)
  values (p_shop_id, target_user_id, p_role)
  on conflict (shop_id, user_id) do update set role = excluded.role;
  return target_user_id;
end;
$$;

create or replace function public.admin_remove_shop_member(p_shop_id uuid, p_user_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare target_role text;
declare admin_count integer;
begin
  if not public.is_shop_admin(p_shop_id) then
    raise exception 'Admin role required';
  end if;
  select role into target_role from public.shop_members where shop_id = p_shop_id and user_id = p_user_id;
  if target_role = 'Admin' then
    select count(*) into admin_count from public.shop_members where shop_id = p_shop_id and role = 'Admin';
    if admin_count <= 1 then raise exception 'Cannot remove the last Admin'; end if;
  end if;
  delete from public.shop_members where shop_id = p_shop_id and user_id = p_user_id;
  return found;
end;
$$;

revoke all on function public.admin_list_shop_members(uuid) from public;
revoke all on function public.admin_add_shop_member_by_email(uuid,text,text) from public;
revoke all on function public.admin_remove_shop_member(uuid,uuid) from public;
grant execute on function public.admin_list_shop_members(uuid) to authenticated;
grant execute on function public.admin_add_shop_member_by_email(uuid,text,text) to authenticated;
grant execute on function public.admin_remove_shop_member(uuid,uuid) to authenticated;
