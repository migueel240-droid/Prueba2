# Tortillería Obregón — aplicación web instalable

Aplicación PWA para ventas, productos, inventario y reparto. Interfaz en español, azul/blanco/amarillo, PIN individual y almacenamiento local para trabajar sin conexión.

## Arquitectura
- `public/`: aplicación web instalable (PWA), caché de archivos y cola local de cambios.
- `server.js`: API central Node.js + Express.
- `data/obregon.sqlite`: base SQLite creada automáticamente en el servidor.
- PIN y permisos se validan en el servidor; no se confía en el rol enviado por el navegador.
- Cada teléfono conserva temporalmente sus operaciones offline y las sincroniza cuando vuelve la conexión.

## Requisitos para publicar
Node.js 20 o posterior. Para usar varios teléfonos, el servidor debe estar publicado en un hosting con almacenamiento persistente y HTTPS. GitHub Pages por sí solo solo sirve los archivos estáticos y **no** ejecuta esta API ni comparte la base de datos.

## Probar en computadora
1. Instala Node.js 20+.
2. Descomprime el paquete y abre una terminal dentro de esta carpeta.
3. Ejecuta `npm install`
4. Copia `.env.example` a `.env` y cambia `SESSION_SECRET` por una cadena larga aleatoria.
5. Ejecuta `npm start`
6. Abre `http://localhost:3000`
7. PIN inicial de administrador: `2468`. **Cámbialo inmediatamente** desde el módulo Usuarios/PIN.

## Publicar
Publica el proyecto completo en un hosting Node.js con disco persistente (por ejemplo, un servicio que soporte Node y almacenamiento persistente), configura `SESSION_SECRET`, `PORT` si el hosting lo requiere y usa HTTPS. No publiques la base SQLite en GitHub. Para uso multi-teléfono, todos deben abrir la misma URL del servidor.

## Primer acceso
- Administrador: PIN `2468` (solo para la instalación inicial).
- Crea los PIN de los repartidores en el módulo Usuarios.
- Los repartidores solo pueden ver su propio balance y sus propias entregas.
- El administrador puede ver los balances individuales y el consolidado.

## Alcance de esta versión
Incluye ventas multi-producto, cobros, catálogo, edición de existencias, asignación de mercancía, devoluciones, cortes y reportes básicos. Es una base funcional inicial: antes de usarla con dinero real, prueba los flujos y configura copias de seguridad del servidor.
