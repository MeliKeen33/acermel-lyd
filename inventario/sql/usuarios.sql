-- ============================================================
--  Pestaña Usuarios: listar cuentas y administrar roles.
--  Pegar entero en el SQL Editor de Supabase. Se puede volver a
--  correr.
--
--  Supone perfiles(id uuid = auth.users.id, nombre, rol).
-- ============================================================


-- ---------- ¿quien llama es admin? ----------
-- SECURITY DEFINER para poder leer perfiles sin pasar por las
-- policies de perfiles (si no, una policy de perfiles que pregunte
-- por perfiles se llama a sí misma).
create or replace function es_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from perfiles where id = auth.uid() and rol = 'admin'
  );
$$;

revoke execute on function es_admin() from public, anon;
grant  execute on function es_admin() to authenticated;


-- ---------- listar cuentas ----------
-- auth.users no se puede leer desde el navegador. Esta función la
-- lee del lado de la base, y solo le responde a un admin.
create or replace function listar_usuarios()
returns table (id uuid, email text, creado timestamptz, nombre text, rol text)
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  if not es_admin() then
    raise exception 'Solo administración puede ver la lista de usuarios'
      using errcode = 'insufficient_privilege';
  end if;

  return query
    select u.id, u.email::text, u.created_at, p.nombre::text, p.rol::text
    from auth.users u
    left join perfiles p on p.id = u.id
    order by (p.id is null) desc, coalesce(p.nombre, u.email);
end;
$$;

revoke execute on function listar_usuarios() from public, anon;
grant  execute on function listar_usuarios() to authenticated;


-- ---------- policies: admin da, cambia y quita acceso ----------
alter table perfiles enable row level security;

-- Lectura: Postgres solo deja editar o borrar filas que se pueden ver.
-- Sin esta, el admin solo ve su propia fila y no puede tocar las demás.
drop policy if exists perfiles_admin_select on perfiles;
create policy perfiles_admin_select on perfiles
  for select to authenticated
  using (es_admin());

drop policy if exists perfiles_admin_insert on perfiles;
create policy perfiles_admin_insert on perfiles
  for insert to authenticated
  with check (es_admin());

drop policy if exists perfiles_admin_update on perfiles;
create policy perfiles_admin_update on perfiles
  for update to authenticated
  using (es_admin() and id <> auth.uid())
  with check (es_admin() and id <> auth.uid());

drop policy if exists perfiles_admin_delete on perfiles;
create policy perfiles_admin_delete on perfiles
  for delete to authenticated
  using (es_admin() and id <> auth.uid());


-- ---------- nadie se cambia ni se quita su propio rol ----------
-- Las policies se suman entre sí: si ya existe otra que deja a cada
-- usuario editar su propia fila, el "id <> auth.uid()" de arriba no
-- alcanza. Este trigger lo garantiza venga de la policy que venga.
-- Desde el SQL Editor auth.uid() es null y no bloquea: si alguna vez
-- hace falta arreglar un rol a mano, se puede.
create or replace function proteger_rol_propio()
returns trigger
language plpgsql
as $$
begin
  if auth.uid() is not null and old.id = auth.uid() then
    if tg_op = 'DELETE' then
      raise exception 'No podés quitarte el acceso a vos mismo'
        using errcode = 'check_violation';
    elsif new.rol is distinct from old.rol or new.id is distinct from old.id then
      raise exception 'No podés cambiarte el rol a vos mismo'
        using errcode = 'check_violation';
    end if;
  end if;
  return case when tg_op = 'DELETE' then old else new end;
end;
$$;

drop trigger if exists proteger_rol_propio on perfiles;
create trigger proteger_rol_propio
  before update or delete on perfiles
  for each row execute function proteger_rol_propio();
