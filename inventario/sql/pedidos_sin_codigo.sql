-- ============================================================
--  Pedidos "No sé qué es esto": planta deja un pedido de alta sin
--  escanear, con descripción, procedencia, dónde lo dejó y una foto
--  opcional en Supabase Storage.
--  Pegar entero en el SQL Editor de Supabase, DESPUÉS de
--  planta_pedidos_alta.sql. Se puede volver a correr.
-- ============================================================


-- ---------- COLUMNAS NUEVAS ----------
-- tipo separa los dos problemas: 'escaneado' (hay un código que no
-- está en el catálogo) y 'sin_codigo' (llegó algo y nadie sabe qué es).
alter table pedidos_alta add column if not exists tipo        text not null default 'escaneado';
alter table pedidos_alta add column if not exists procedencia text;   -- de dónde vino, si se sabe
alter table pedidos_alta add column if not exists ubicacion   text;   -- dónde lo dejó
alter table pedidos_alta add column if not exists foto        text;   -- ruta en el bucket pedidos-alta

-- Un pedido sin código no tiene código: deja de ser obligatorio, pero
-- solo para ese tipo (la regla de abajo lo exige para los escaneados).
alter table pedidos_alta alter column codigo drop not null;

alter table pedidos_alta drop constraint if exists pedidos_alta_tipo_valido;
alter table pedidos_alta add  constraint pedidos_alta_tipo_valido
  check (tipo in ('escaneado', 'sin_codigo'));

alter table pedidos_alta drop constraint if exists pedidos_alta_codigo_segun_tipo;
alter table pedidos_alta add  constraint pedidos_alta_codigo_segun_tipo check (
  (tipo = 'escaneado'  and codigo is not null) or
  (tipo = 'sin_codigo' and codigo is null)
);

-- Sin código, dónde lo dejó es obligatorio: sin eso no se encuentra.
alter table pedidos_alta drop constraint if exists pedidos_alta_ubicacion_sin_codigo;
alter table pedidos_alta add  constraint pedidos_alta_ubicacion_sin_codigo
  check (tipo <> 'sin_codigo' or ubicacion is not null);

alter table pedidos_alta drop constraint if exists pedidos_alta_textos_largo;
alter table pedidos_alta add  constraint pedidos_alta_textos_largo check (
  (procedencia is null or length(procedencia) between 1 and 200) and
  (ubicacion   is null or length(ubicacion)   between 1 and 200)
);

-- La foto tiene que estar en la carpeta de quien hizo el pedido.
alter table pedidos_alta drop constraint if exists pedidos_alta_foto_propia;
alter table pedidos_alta add  constraint pedidos_alta_foto_propia
  check (foto is null or split_part(foto, '/', 1) = pedido_por::text);


-- ---------- TRIGGER ----------
-- Reemplaza al de planta_pedidos_alta.sql: hace lo mismo y además
-- limpia y protege las columnas nuevas.
create or replace function pedidos_alta_sellar()
returns trigger
language plpgsql
as $$
begin
  if tg_op = 'INSERT' then
    new.codigo       := upper(btrim(new.codigo));
    new.descripcion  := btrim(new.descripcion);
    new.procedencia  := nullif(btrim(new.procedencia), '');
    new.ubicacion    := nullif(btrim(new.ubicacion), '');
    new.foto         := nullif(btrim(new.foto), '');
    new.pedido_por   := auth.uid();
    new.pedido_en    := now();
    new.resuelto     := false;
    new.resuelto_por := null;
    new.resuelto_en  := null;
  else
    -- Lo pedido no se reescribe.
    if new.codigo      is distinct from old.codigo
    or new.descripcion is distinct from old.descripcion
    or new.tipo        is distinct from old.tipo
    or new.procedencia is distinct from old.procedencia
    or new.ubicacion   is distinct from old.ubicacion
    or new.foto        is distinct from old.foto
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


-- ---------- BUCKET DE FOTOS ----------
-- Privado: las fotos se ven con un link firmado que dura una hora.
-- Hasta 5 MB por foto (la pantalla las achica antes de subirlas) y
-- solo imágenes.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('pedidos-alta', 'pedidos-alta', false, 5242880, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update
  set public             = excluded.public,
      file_size_limit    = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- Subir: planta y admin, y solo dentro de su propia carpeta (<su id>/...).
drop policy if exists pedidos_alta_fotos_subir on storage.objects;
create policy pedidos_alta_fotos_subir on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'pedidos-alta'
    and (storage.foldername(name))[1] = auth.uid()::text
    and public.rol_actual() in ('planta', 'admin')
  );

-- Ver: admin todas; cada uno las suyas.
drop policy if exists pedidos_alta_fotos_ver on storage.objects;
create policy pedidos_alta_fotos_ver on storage.objects
  for select to authenticated
  using (
    bucket_id = 'pedidos-alta'
    and (public.rol_actual() = 'admin' or (storage.foldername(name))[1] = auth.uid()::text)
  );

-- Sin policies de UPDATE ni DELETE: la foto queda como evidencia del
-- pedido, igual que el pedido mismo.
