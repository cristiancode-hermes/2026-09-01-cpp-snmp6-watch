# Arquitectura — snmp6-watch

## Flujo

```
/proc/net/snmp6  ──►  load_snapshot()  ──►  Snapshot{ts, counters[86]}
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    ▼                          ▼                          ▼
             render_snapshot()          render_delta()             render_json()
             (tabla + histograma)       (watch: solo cambios)     (summary + counters)
```

## Estructura de datos

- `Counter { name, value }` — un contador SNMP6; `fam()` / `dir()` / `kind()`
  se derivan del nombre (`Ip6`/`Icmp6`/`Udp6`/`UdpLite6`, In/Out/Reasm/Frag,
  error/octets/nd/mld/echo/ecn/mcast/traffic).
- `Snapshot` — vector de 86 contadores + agregados (`fam_count`, `kind_total`,
  `named`, `nonzero_count`) y lookup por nombre (`find`) para los deltas.
- `Filters { fam, dir, kind, key, nonzero, top }` — criterios de filtrado,
  evaluados por `passes()`. `--top N` ordena descendente **después** del filtro.

## Parsing

Cada línea: `Nombre<sep>valor<newline>` donde `<sep>` es tab o 2+ espacios.
El parser tolera comentarios `#`, filas malformadas, espacios alrededor del
nombre y CR de Windows.

El valor se parsea con `std::from_chars` tras recortar whitespace (from_chars
NO salta espacios — pitfall conocido).

**Pitfall de familia**: `UdpLite6*` comparte prefijo con `Udp6*`. Hay que
clasificar `UdpLite6` **antes** de `Udp6`.

**Pitfall de dirección**: `Ip6ReasmOKs` contiene tanto `Reasm` como no `In`;
`Reasm`/`Frag` se evalúan antes que `In`/`Out`.

## Renderizado

- Histograma: 0 → `.`, 1-999 → `#` azul, 1K-999K → `##`, ≥1M → `###` amarillo.
  Errores no-cero se pintan en rojo.
- Octetos se muestran humanizados (`9.80G`) en la tabla; JSON lleva el valor crudo.
- Paleta ANSI **mutable** — `--no-color` la vacía de verdad.

## Decisiones

- **C++23 stdlib-only**: cero dependencias; g++ directo.
- **Complemento de snmp-watch**: IPv4 vive en `/proc/net/snmp` + `netstat`;
  IPv6 vive en este fichero de un contador por línea (no la matriz
  header+values de snmp IPv4).
- **`--demo`**: host dual-stack sintético con 86 filas para que la herramienta
  muestre ND, reensamblado y GBytes de tráfico en un host sin IPv6 real.
