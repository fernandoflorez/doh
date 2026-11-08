Proxy DNS-over-HTTPS
=====================

Pequeño proyecto en RUST para DoH.

Expone un servidor UDP en puerto 53 (DNS) y realiza un request de resolución de dominio a uno de los servidores públicos de DNS-over-HTTPS:

- Google (8.8.8.8)
- Cloudflare (1.1.1.1)
- Quad9 (9.9.9.9)
- OpenDNS (208.67.222.222)
- Mullvad (194.242.2.2)


Al recibir una solicitud de resolv realiza una carrera (race) entre todos los proveedores de DNS registrados y retorna el primer resultado obtenido.

Se agrega soporte para blocklists (bloqueo de ads por ejemplo ala PI-Hole):

- Descargar una blocklist, ej: https://v.firebog.net/hosts/AdguardDNS.txt
- Se tiene un argument --blocklist donde se le pasa el .txt descargado:

```cargo run --blocklist AdguardDNS.txt```


Para eliminar los registros:

```cargo run --clear```


Los hostnames se almacenan en sqlite. Por defecto el nombre es 'doh_blocklist.db' pero puede cambiarse con --db-path.


Por defecto escucha en `127.0.0.1:53`, que es el puerto que usa la configuración DNS del sistema. Para usar el puerto 53 hace falta ejecutarlo con sudo (en Linux se puede evitar con `sudo setcap cap_net_bind_service=+ep target/release/doh`).

Para escuchar en otra dirección o puerto se usa --listen:

```cargo run -- --listen 127.0.0.1:5300```

```dig @127.0.0.1 -p 5300 example.com```

Atiende consultas por UDP y TCP. Las respuestas que no entran en UDP se marcan como truncadas para que el cliente reintente por TCP.

Por defecto no registra cada consulta. Para ver consultas, aciertos de caché, bloqueos y el servidor ganador:

```cargo run -- --verbose```

Las respuestas se guardan en caché en memoria respetando su TTL (hasta 10.000 entradas). La blocklist se carga en memoria al iniciar y bloquea también los subdominios de cada dominio de la lista.


Ideas para después:

- [ ] Poder tener estadísticas de cuál proveedor de DNS es más rápido
- [ ] Poder tener estadísticas de bloqueos por hostname
- [ ] Servicio de autostart para iniciado automático

**Importante: Esto no evita DNS leaks**
