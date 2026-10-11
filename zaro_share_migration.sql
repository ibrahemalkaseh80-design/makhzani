-- ZARO secure sharing invitations (Partner / Staff)
-- Review, then run once in Supabase SQL Editor. This migration changes access policies:
-- Admin + Partner can manage shop data; Staff can only search products through a restricted RPC.

create table if not exists public.shop_share_invites (
  id uuid primary key default gen_random_uuid(),
  shop_id uuid not null references public.shops(id) on delete cascade,
  target_email text not null,
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  role text not null check (role in ('Partner','Staff')),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '48 hours'),
  used_at timestamptz
);

alter table public.shop_share_invites enable row level security;
revoke all on public.shop_share_invites from anon, authenticated;

-- Remove older broad membership policies from tables whose access is controlled below.
do $$
declare p record;
begin
  for p in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in ('shops','products','sales_reps','reminders','daily_sessions','daily_stock_counts','shop_members')
  loop
    execute format('drop policy if exists %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end $$;

alter table public.shops enable row level security;
alter table public.products enable row level security;
alter table public.sales_reps enable row level security;
alter table public.reminders enable row level security;
alter table public.daily_sessions enable row level security;
alter table public.daily_stock_counts enable row level security;
alter table public.shop_members enable row level security;

create or replace function public.is_shop_partner(p_shop_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.shop_members sm
    where sm.shop_id = p_shop_id
      and sm.user_id = auth.uid()
      and sm.role = 'Partner'
  );
$$;

create or replace function public.current_shop_role(p_shop_id uuid)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select sm.role
  from public.shop_members sm
  where sm.shop_id = p_shop_id and sm.user_id = auth.uid()
  limit 1;
$$;

revoke all on function public.is_shop_partner(uuid) from public;
revoke all on function public.current_shop_role(uuid) from public;
grant execute on function public.is_shop_partner(uuid) to authenticated;
grant execute on function public.current_shop_role(uuid) to authenticated;

-- Allow the new Partner role if the existing schema has a role check constraint.
do $$
declare c record;
begin
  for c in
    select conname
    from pg_constraint
    where conrelid = 'public.shop_members'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%role%'
  loop
    execute format('alter table public.shop_members drop constraint %I', c.conname);
  end loop;
end $$;

alter table public.shop_members
  add constraint shop_members_role_allowed
  check (role in ('Admin','Partner','Coordinator','Staff'));

-- Shop visibility and settings: all members can see the shop; only Admin/Partner can edit.
create policy shops_select_members on public.shops
  for select to authenticated
  using (public.is_shop_member(id));

create policy shops_update_managers on public.shops
  for update to authenticated
  using (public.is_shop_admin(id) or public.is_shop_partner(id))
  with check (public.is_shop_admin(id) or public.is_shop_partner(id));

-- Inventory is not directly readable by Staff. Their only route is employee_search_products().
create policy products_manage_managers on public.products
  for all to authenticated
  using (public.is_shop_admin(shop_id) or public.is_shop_partner(shop_id))
  with check (public.is_shop_admin(shop_id) or public.is_shop_partner(shop_id));

create policy sales_reps_manage_managers on public.sales_reps
  for all to authenticated
  using (public.is_shop_admin(shop_id) or public.is_shop_partner(shop_id))
  with check (public.is_shop_admin(shop_id) or public.is_shop_partner(shop_id));

create policy reminders_manage_managers on public.reminders
  for all to authenticated
  using (public.is_shop_admin(shop_id) or public.is_shop_partner(shop_id))
  with check (public.is_shop_admin(shop_id) or public.is_shop_partner(shop_id));

create policy daily_sessions_manage_managers on public.daily_sessions
  for all to authenticated
  using (public.is_shop_admin(shop_id) or public.is_shop_partner(shop_id))
  with check (public.is_shop_admin(shop_id) or public.is_shop_partner(shop_id));

create policy daily_stock_counts_manage_managers on public.daily_stock_counts
  for all to authenticated
  using (exists (
    select 1 from public.daily_sessions ds
    where ds.id = session_id
      and (public.is_shop_admin(ds.shop_id) or public.is_shop_partner(ds.shop_id))
  ))
  with check (exists (
    select 1 from public.daily_sessions ds
    where ds.id = session_id
      and (public.is_shop_admin(ds.shop_id) or public.is_shop_partner(ds.shop_id))
  ));

-- No direct client reads/writes to shop_members; membership is managed only through guarded RPCs.
-- The Admin-only functions admin_list_shop_members/admin_add_shop_member_by_email/admin_remove_shop_member
-- remain the account-management interface. Partner is not an Admin and cannot use those functions.

create or replace function public.admin_create_shop_invite(
  p_shop_id uuid,
  p_email text,
  p_role text,
  p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare invite_id uuid;
begin
  if not public.is_shop_admin(p_shop_id) then
    raise exception 'Admin role required';
  end if;
  if p_role not in ('Partner','Staff') then
    raise exception 'Invalid sharing role';
  end if;
  if nullif(trim(p_email),'') is null or position('@' in trim(p_email)) < 2 then
    raise exception 'Valid email required';
  end if;
  if p_token_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'Invalid invitation token';
  end if;

  insert into public.shop_share_invites(shop_id,target_email,token_hash,role,created_by)
  values (p_shop_id, lower(trim(p_email)), p_token_hash, p_role, auth.uid())
  returning id into invite_id;

  return jsonb_build_object('invite_id', invite_id, 'role', p_role, 'expires_at', now() + interval '48 hours');
end;
$$;

create or replace function public.accept_shop_invite(p_token_hash text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  inv public.shop_share_invites%rowtype;
  user_email text;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  if p_token_hash !~ '^[0-9a-f]{64}$' then raise exception 'Invalid invitation'; end if;

  select * into inv
  from public.shop_share_invites
  where token_hash = p_token_hash
  for update;

  if not found then raise exception 'Invitation not found'; end if;
  if inv.used_at is not null then raise exception 'Invitation already used'; end if;
  if inv.expires_at <= now() then raise exception 'Invitation expired'; end if;

  select lower(trim(email)) into user_email from auth.users where id = auth.uid();
  if user_email is null or user_email <> lower(trim(inv.target_email)) then
    raise exception 'Sign in with the email address this invitation was created for';
  end if;

  if exists (
    select 1 from public.shop_members
    where shop_id = inv.shop_id and user_id = auth.uid()
  ) then
    raise exception 'This account is already a member of the shop';
  end if;

  insert into public.shop_members(shop_id,user_id,role)
  values (inv.shop_id,auth.uid(),inv.role);

  update public.shop_share_invites set used_at = now() where id = inv.id;
  return inv.shop_id;
end;
$$;

create or replace function public.employee_search_products(p_shop_id uuid, p_query text)
returns table(
  id uuid,
  name text,
  barcode text,
  sale_price numeric,
  category text,
  quantity integer,
  purchase_price numeric,
  sales_rep text,
  sales_rep_phone text
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare q text := lower(trim(coalesce(p_query,'')));
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  if public.current_shop_role(p_shop_id) not in ('Staff','Admin','Partner') then
    raise exception 'Shop membership required';
  end if;
  if q = '' then return; end if;

  return query
    select p.id, p.name::text, p.barcode::text, p.sale_price,
           coalesce(p.category,'أخرى')::text, p.quantity::integer,
           p.purchase_price, p.sales_rep::text, p.sales_rep_phone::text
    from public.products p
    where p.shop_id = p_shop_id
      and (
        lower(coalesce(p.name,'')) like '%' || q || '%'
        or lower(coalesce(p.barcode,'')) like '%' || q || '%'
        or lower(coalesce(p.category,'')) like '%' || q || '%'
      )
    order by p.created_at desc
    limit 50;
end;
$$;

revoke all on function public.admin_create_shop_invite(uuid,text,text,text) from public;
revoke all on function public.accept_shop_invite(text) from public;
revoke all on function public.employee_search_products(uuid,text) from public;
grant execute on function public.admin_create_shop_invite(uuid,text,text,text) to authenticated;
grant execute on function public.accept_shop_invite(text) to authenticated;
grant execute on function public.employee_search_products(uuid,text) to authenticated;
