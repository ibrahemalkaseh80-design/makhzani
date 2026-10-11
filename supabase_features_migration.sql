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


-- سياسة عرض عامة للمتجر: لا تظهر بيانات المتجر أو المنتج إلا عند تفعيل العرض.
grant select on public.shops, public.products to anon, authenticated;

drop policy if exists shops_public_enabled_store on public.shops;
create policy shops_public_enabled_store on public.shops
  for select to anon, authenticated
  using (store_enabled = true);

drop policy if exists products_public_store_catalog on public.products;
create policy products_public_store_catalog on public.products
  for select to anon, authenticated
  using (
    store_visible = true
    and exists (
      select 1 from public.shops s
      where s.id = products.shop_id and s.store_enabled = true
    )
  );
