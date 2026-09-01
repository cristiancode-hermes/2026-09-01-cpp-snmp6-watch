# snmp6-watch

Monitor de contadores **SNMP IPv6 del kernel Linux** en C++23, zero deps.

Lee `/proc/net/snmp6` (exportado por `net/ipv6/proc.c`, función `snmp6_seq_show`)
y muestra los **86 contadores** de la MIB IPv6: `Ip6` (33), `Icmp6` (36),
`Udp6` (9) y `UdpLite6` (8) — clasificados por familia, dirección
(`in` / `out` / `reasm` / `frag`) y semántica (`error`, `octets`, `nd`,
`mld`, `echo`, `ecn`, `mcast`, `traffic`).

Complementa a `snmp-watch` (IPv4 `/proc/net/snmp` + `/proc/net/netstat`):
este proyecto cubre **solo** el lado IPv6.

## Features

- **Fuente única**: `/proc/net/snmp6` — 86 contadores `Ip6*` / `Icmp6*` / `Udp6*` / `UdpLite6*`
- **Familia**: `ip6` (33), `icmp6` (36), `udp6` (9), `udplite6` (8) — `UdpLite6` se discrimina **antes** de `Udp6` (prefijo compartido)
- **Dirección**: `in` / `out` / `reasm` / `frag` / `other` (`Reasm` y `Frag` ganan sobre `In`)
- **Semántica**: `error`, `octets`, `nd` (Neighbor Discovery), `mld`, `echo`, `ecn`, `mcast`, `traffic`
- **Octetos humanizados**: 9.80G / 7.20M / 540.0K en la tabla (valores crudos en JSON)
- **`--top N`**: ordena por valor descendente (empates permitidos)
- **Resumen**: recuento por familia, in/out octets, ND total, errores
- **Modo watch (`--watch N`)**: refresh periódico con deltas y flush por frame en pipes
- **Salida JSON (`--json`)**: `summary` + array `counters` validable con `python -m json.tool`
- **Demo mode (`--demo`)**: host dual-stack IPv6 sintético ocupado (86 contadores, ND, reensamblado, 9.8G in-octets)
- **Filtros**: `--fam`, `--dir`, `--kind`, `--key PREFIX`, `--nonzero`, `--top N`
- **`--file`**: parsea un dump (tolera comentarios `#`, blancos y filas basura)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: clasificación, parser, `--file` del workflow real, demo, filtros, JSON, `--no-color`, watch/deltas, `/proc` real

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o snmp6-watch
```

## Usage

```bash
# Snapshot único (host real)
./snmp6-watch

# Solo contadores con valor > 0
./snmp6-watch --nonzero

# Solo familia ICMPv6
./snmp6-watch --fam icmp6

# Neighbor Discovery
./snmp6-watch --kind nd

# Top 10 por valor
./snmp6-watch --top 10

# Modo watch (cada 2s) con deltas
./snmp6-watch --watch 2

# JSON
./snmp6-watch --json

# Demo (host dual-stack sintético)
./snmp6-watch --demo

# Parsear un dump con comentarios
./snmp6-watch --file sample-snmp6.table --no-color

# Sin colores
./snmp6-watch --no-color

# Auto-tests
./snmp6-watch --selftest
```

## Formato de `/proc/net/snmp6`

```
Ip6InReceives                  	901472
Ip6InHdrErrors                 	0
...
UdpLite6MemErrors              	0
```

Cada línea: `Nombre<espacios/tab>valor`. Los nombres coinciden con
`linux_mib6` / `icmpv6_mib` / `udp_mib` en `include/uapi/linux/snmp.h` y se
incrementan desde `net/ipv6/ip6_input.c`, `ip6_output.c`, `icmp.c` y
`net/ipv6/udp.c`.

## Selftest

```bash
./snmp6-watch --selftest
# selftest: 62 passed, 0 failed
```
