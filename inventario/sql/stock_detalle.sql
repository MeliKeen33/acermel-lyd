-- ============================================================
--  Vista stock_detalle: el stock de cada producto con su tipo,
--  etapa, origen y fecha del último movimiento, para filtrar,
--  mostrar y exportar en la pestaña Stock.
--  Pegar entero en el SQL Editor de Supabase. Se puede volver a
--  correr.
--
--  Por qué una vista nueva y no cambiar stock: no toca la
--  definición de stock (que sigue siendo la única fuente del
--  saldo, calculado desde movimientos) y solo usa columnas que
--  stock ya tiene. No guarda ningún número: es otra vista.
--
--  security_invoker: se lee con los permisos de quien consulta,
--  así que las policies de RLS de productos y movimientos siguen
--  aplicando.
--
--  ultimo_movimiento usa fecha (cuándo pasó en planta), no
--  registrado (cuándo se cargó), igual que todo lo que es saldo.
--
--  Las columnas nuevas van al final: create or replace view solo
--  deja agregar columnas después de las que ya existen.
-- ============================================================

create or replace view stock_detalle
with (security_invoker = true)
as
select s.codigo,
       s.descripcion,
       s.stock,
       s.posicion,
       p.tipo,
       p.etapa,
       p.origen,
       (select max(m.fecha) from movimientos m where m.producto = s.codigo) as ultimo_movimiento
from stock s
join productos p on p.codigo = s.codigo;

revoke all on stock_detalle from anon;
grant select on stock_detalle to authenticated;
