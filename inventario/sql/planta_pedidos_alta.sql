-- ============================================================
--  Pantalla de planta: pedidos de alta y posición desde planta.
--  Pegar entero en el SQL Editor de Supabase. Se puede volver a
--  correr.
--
--  Supone:
--    perfiles(id uuid = auth.uid(), nombre, rol)  rol: planta | admin | gerencia
--    productos(codigo, posicion, ...)
-- ============================================================


-- Rol de quien llama. SECURITY DEFINER para que las policies no
-- dependan de lo que la RLS de perfiles deje leer.
create or replace function rol_actual()
returns text
language sql stable
security definer
set search_path = public
as $$
  select rol from perfiles where id = auth.uid();
$$;
revoke execute on function rol_actual() from public, anon;
grant execute on function rol_actual() to authenticated;


-- ---------- PEDIDOS DE ALTA ----------
-- Un código escaneado en planta que no está en el catálogo. No es
-- un producto: es un aviso para administración. No mueve stock.
create table if not exists pedidos_alta (
  id           bigint generated always as identity primary key,
  codigo       text not null,
  descripcion  text not null,
  pedido_por   uuid not null default auth.uid() references perfiles(id),
  pedido_en    timestamptz not null default now(),
  resuelto     boolean not null default false,
  resuelto_por uuid references perfiles(id),
  resuelto_en  timestamptz,

  constraint pedidos_alta_codigo_lleno      check (length(btrim(codigo)) between 1 and 60),
  constraint pedidos_alta_descripcion_llena check (length(btrim(descripcion)) between 1 and 200),
  -- Resuelto y sus datos van juntos: o están los tres o ninguno.
  constraint pedidos_alta_resuelto_completo check (
    (resuelto and resuelto_por is not null and resuelto_en is not null) or
    (not resuelto and resuelto_por is null and resuelto_en is null)
  )
);

-- Un solo pedido abierto por código: si dos operarios escanean el
-- mismo código desconocido, el segundo no duplica el pedido.
create unique index if not exists pedidos_alta_un_abierto_por_codigo
  on pedidos_alta (upper(codigo)) where not resuelto;

create index if not exists pedidos_alta_abiertos
  on pedidos_alta (pedido_en) where not resuelto;


-- Quién y cuándo los pone la base, no la pantalla.
create or replace function pedidos_alta_sellar()
returns trigger
language plpgsql
as $$
begin
  if tg_op = 'INSERT' then
    new.codigo       := upper(btrim(new.codigo));
    new.descripcion  := btrim(new.descripcion);
    new.pedido_por   := auth.uid();
    new.pedido_en    := now();
    new.resuelto     := false;
    new.resuelto_por := null;
    new.resuelto_en  := null;
  else
    -- Lo pedido no se reescribe.
    if new.codigo      is distinct from old.codigo
    or new.descripcion is distinct from old.descripcion
    or new.pedido_por  is distinct from old.pedido_por
    or new.pedido_en   is distinct from old.pedido_en then
      raise exception 'Un pedido de alta no se puede modificar, solo marcar como resuelto'
        using errcode = 'check_violation';
    end if;
    if new.resuelto and not old.resuelto then
      new.resuelto_por := auth.uid();
      new.resuelto_en  := now();
    elsif new.resuelto is distinct from old.resuelto then
      raise exception 'Un pedido resuelto no se reabre: si hace falta, que planta lo pida de nuevo'
        using errcode = 'check_violation';
    else
      new.resuelto_por := old.resuelto_por;
      new.resuelto_en  := old.resuelto_en;
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists pedidos_alta_sellar on pedidos_alta;
create trigger pedidos_alta_sellar
  before insert or update on pedidos_alta
  for each row execute function pedidos_alta_sellar();


-- ---------- RLS ----------
alter table pedidos_alta enable row level security;

-- Pedir: planta y admin, siempre a su nombre.
drop policy if exists pedidos_alta_insert on pedidos_alta;
create policy pedidos_alta_insert on pedidos_alta
  for insert to authenticated
  with check (rol_actual() in ('planta', 'admin') and pedido_por = auth.uid());

-- Ver: admin todos; planta solo los suyos.
drop policy if exists pedidos_alta_select on pedidos_alta;
create policy pedidos_alta_select on pedidos_alta
  for select to authenticated
  using (rol_actual() = 'admin' or pedido_por = auth.uid());

-- Resolver: solo admin. El trigger impide tocar otra cosa.
drop policy if exists pedidos_alta_update on pedidos_alta;
create policy pedidos_alta_update on pedidos_alta
  for update to authenticated
  using (rol_actual() = 'admin')
  with check (rol_actual() = 'admin');

-- Sin policy de DELETE: queda el registro de qué se pidió y quién lo resolvió.

revoke all on pedidos_alta from anon;
grant select, insert on pedidos_alta to authenticated;
grant update (resuelto) on pedidos_alta to authenticated;


-- ---------- POSICIÓN DESDE PLANTA ----------
-- Planta no edita productos. Esta función le deja hacer una sola
-- cosa: completar la posición de un producto que no la tiene.
-- Si ya tiene una, no la pisa: cambiarla es tarea de administración.
create or replace function cargar_posicion(p_codigo text, p_posicion text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_pos text := upper(btrim(p_posicion));
begin
  if coalesce(rol_actual(), '') not in ('planta', 'admin') then
    raise exception 'Solo planta y administración pueden cargar posiciones'
      using errcode = 'insufficient_privilege';
  end if;
  if v_pos is null or length(v_pos) not between 1 and 20 then
    raise exception 'La posición tiene que tener entre 1 y 20 caracteres'
      using errcode = 'check_violation';
  end if;

  update productos set posicion = v_pos
  where codigo = p_codigo and nullif(btrim(posicion), '') is null;

  if not found then
    if exists (select 1 from productos where codigo = p_codigo) then
      raise exception 'El producto % ya tiene posición cargada. Para cambiarla, avisá a administración.', p_codigo
        using errcode = 'check_violation';
    end if;
    raise exception 'El producto % no existe', p_codigo;
  end if;
end;
$$;

revoke execute on function cargar_posicion(text, text) from public, anon;
grant execute on function cargar_posicion(text, text) to authenticated;
