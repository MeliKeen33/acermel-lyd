-- ============================================================
--  Pestaña Movimientos registrados (admin y gerencia) y últimos
--  movimientos en la ficha de Editar producto.
--  Pegar entero en el SQL Editor de Supabase, DESPUÉS de
--  planta_pedidos_alta.sql (usa rol_actual()). Se puede volver a
--  correr.
-- ============================================================


-- ---------- VISTA DEL LIBRO ----------
-- El libro con la descripción del producto y el nombre de quién cargó.
--
-- Por qué no es security_invoker como stock_detalle: gerencia solo
-- puede leer su propia fila de perfiles, así que con sus permisos no
-- vería quién cargó cada movimiento. La vista lee con los permisos de
-- su dueño y el filtro de abajo decide quién la ve: admin y gerencia.
-- Para cualquier otro rol la vista no devuelve filas.
-- (El linter de Supabase la marca como "security definer view": es
-- a propósito, por lo de arriba.)
--
-- usuario se compara como texto para no depender de si la columna es
-- uuid o text.
create or replace view movimientos_detalle as
select m.id,
       m.fecha,
       m.producto,
       p.descripcion,
       m.cantidad,
       m.motivo,
       m.nota,
       m.usuario,
       pf.nombre as usuario_nombre,
       m.registrado
from movimientos m
left join productos p  on p.codigo = m.producto
left join perfiles  pf on pf.id::text = m.usuario::text
where public.rol_actual() in ('admin', 'gerencia');

revoke all on movimientos_detalle from anon;
grant select on movimientos_detalle to authenticated;


-- ---------- USUARIOS PARA EL FILTRO ----------
create or replace function usuarios_del_libro()
returns table (id text, nombre text)
language sql
stable
security definer
set search_path = public
as $$
  select p.id::text, p.nombre::text
  from perfiles p
  where rol_actual() in ('admin', 'gerencia')
  order by p.nombre;
$$;

revoke execute on function usuarios_del_libro() from public, anon;
grant  execute on function usuarios_del_libro() to authenticated;


-- ---------- ÍNDICES ----------
-- El libro va a crecer mucho más que el catálogo. La pantalla lo lee
-- del más reciente al más viejo (fecha, y a igual fecha el último
-- cargado primero: id) y pide "los siguientes" a partir de la última
-- fila vista, no por número de página: así no se repiten ni se saltean
-- filas si entran movimientos nuevos mientras se mira la lista.
create index if not exists movimientos_orden_libro on movimientos (fecha desc, id desc);
create index if not exists movimientos_por_producto on movimientos (producto, fecha desc);
create index if not exists movimientos_por_usuario  on movimientos (usuario);
