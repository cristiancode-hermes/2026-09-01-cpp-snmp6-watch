// SPDX-License-Identifier: MIT
// cpp-snmp6-watch — IPv6 SNMP MIB counters from /proc/net/snmp6
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o snmp6-watch
// Usage: ./snmp6-watch [--fam ip6|icmp6|udp6|udplite6] [--dir in|out|reasm|frag]
//                      [--kind error|octets|nd|mld|echo|ecn|mcast|traffic]
//                      [--key PREFIX] [--nonzero] [--top N]
//                      [--watch N] [--json] [--demo] [--file PATH]
//                      [--no-color] [--selftest]

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

static void enable_color() {
  C_RESET = "\x1b[0m"; C_BOLD = "\x1b[1m"; C_DIM = "\x1b[2m";
  C_RED = "\x1b[31m"; C_GREEN = "\x1b[32m"; C_YELLOW = "\x1b[33m";
  C_BLUE = "\x1b[34m"; C_CYAN = "\x1b[36m"; C_MAGENTA = "\x1b[35m";
}

// ─────────────────────────────────────────────────────────────────────────────
// Model — one IPv6 SNMP counter (net/ipv6/proc.c, snmp6_seq_show)
// ─────────────────────────────────────────────────────────────────────────────
enum class Fam { Ip6, Icmp6, Udp6, UdpLite6, Unknown };
enum class Dir { In, Out, Reasm, Frag, Other };
enum class Kind { Error, Octets, Nd, Mld, Echo, Ecn, Mcast, Traffic, Other };

static Fam fam_of(std::string_view n) {
  // UdpLite6 must be checked before Udp6 (shared prefix)
  if (n.starts_with("UdpLite6")) return Fam::UdpLite6;
  if (n.starts_with("Udp6"))     return Fam::Udp6;
  if (n.starts_with("Icmp6"))    return Fam::Icmp6;
  if (n.starts_with("Ip6"))      return Fam::Ip6;
  return Fam::Unknown;
}

static const char* fam_name(Fam f) {
  switch (f) {
    case Fam::Ip6:      return "ip6";
    case Fam::Icmp6:    return "icmp6";
    case Fam::Udp6:     return "udp6";
    case Fam::UdpLite6: return "udplite6";
    default:            return "?";
  }
}

static Dir dir_of(std::string_view n) {
  if (n.find("Reasm") != std::string_view::npos) return Dir::Reasm;
  if (n.find("Frag")  != std::string_view::npos) return Dir::Frag;
  if (n.find("Out")   != std::string_view::npos) return Dir::Out;
  if (n.find("In")    != std::string_view::npos) return Dir::In;
  return Dir::Other;  // e.g. Udp6NoPorts, Udp6MemErrors
}

static const char* dir_name(Dir d) {
  switch (d) {
    case Dir::In:    return "in";
    case Dir::Out:   return "out";
    case Dir::Reasm: return "reasm";
    case Dir::Frag:  return "frag";
    default:         return "other";
  }
}

static Kind kind_of(std::string_view n) {
  if (n.find("Octets") != std::string_view::npos) return Kind::Octets;
  if (n.find("Neighbor") != std::string_view::npos) return Kind::Nd;
  if (n.find("GroupMemb") != std::string_view::npos || n.find("MLD") != std::string_view::npos)
    return Kind::Mld;
  if (n.find("Echo") != std::string_view::npos) return Kind::Echo;
  if (n.find("ECT") != std::string_view::npos || n.find("CEPkts") != std::string_view::npos)
    return Kind::Ecn;
  if (n.find("Mcast") != std::string_view::npos) return Kind::Mcast;
  if (n.find("Error") != std::string_view::npos || n.find("TooBig") != std::string_view::npos ||
      n.find("NoRoutes") != std::string_view::npos || n.find("AddrError") != std::string_view::npos ||
      n.find("Truncated") != std::string_view::npos || n.find("Discard") != std::string_view::npos ||
      n.find("NoPorts") != std::string_view::npos || n.find("RateLimit") != std::string_view::npos ||
      n.find("UnknownProto") != std::string_view::npos || n.find("Csum") != std::string_view::npos ||
      n.find("MemError") != std::string_view::npos || n.find("Rcvbuf") != std::string_view::npos ||
      n.find("Sndbuf") != std::string_view::npos || n.find("TimeExcd") != std::string_view::npos ||
      n.find("ParmProblem") != std::string_view::npos || n.find("DestUnreach") != std::string_view::npos)
    return Kind::Error;
  return Kind::Traffic;
}

static const char* kind_name(Kind k) {
  switch (k) {
    case Kind::Error:   return "error";
    case Kind::Octets:  return "octets";
    case Kind::Nd:      return "nd";
    case Kind::Mld:     return "mld";
    case Kind::Echo:    return "echo";
    case Kind::Ecn:     return "ecn";
    case Kind::Mcast:   return "mcast";
    case Kind::Traffic: return "traffic";
    default:            return "other";
  }
}

struct Counter {
  std::string name;
  unsigned long long value = 0;

  Fam  fam()  const { return fam_of(name); }
  Dir  dir()  const { return dir_of(name); }
  Kind kind() const { return kind_of(name); }
  bool nonzero() const { return value != 0; }
};

struct Snapshot {
  long long ts = 0;
  std::vector<Counter> counters;

  const Counter* find(std::string_view name) const {
    auto it = std::find_if(counters.begin(), counters.end(),
                           [name](const Counter& c) { return c.name == name; });
    return it == counters.end() ? nullptr : &*it;
  }

  unsigned long long fam_total(Fam f) const {
    unsigned long long t = 0;
    for (const auto& c : counters)
      if (c.fam() == f) t += c.value;
    return t;
  }

  unsigned long long kind_total(Kind k) const {
    unsigned long long t = 0;
    for (const auto& c : counters)
      if (c.kind() == k) t += c.value;
    return t;
  }

  unsigned long long named(std::string_view n) const {
    const Counter* c = find(n);
    return c ? c->value : 0;
  }

  unsigned long long total() const {
    unsigned long long t = 0;
    for (const auto& c : counters) t += c.value;
    return t;
  }

  std::size_t fam_count(Fam f) const {
    return static_cast<std::size_t>(
      std::count_if(counters.begin(), counters.end(),
                    [f](const Counter& c) { return c.fam() == f; }));
  }

  std::size_t nonzero_count() const {
    return static_cast<std::size_t>(
      std::count_if(counters.begin(), counters.end(),
                    [](const Counter& c) { return c.nonzero(); }));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Loaders
// ─────────────────────────────────────────────────────────────────────────────
static unsigned long long parse_u64(std::string_view s) {
  unsigned long long v = 0;
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return 0;
  s.remove_prefix(start);
  std::from_chars(s.data(), s.data() + s.size(), v);
  return v;
}

// Format: "Ip6InReceives                   \t901472"
// Tolerates blank lines and '#' comments (--file dumps).
static bool load_snapshot(Snapshot& snap, const std::string& path) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  snap.counters.clear();
  while (std::getline(f, line)) {
    if (line.empty()) continue;
    size_t hash = line.find_first_of('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
      line.pop_back();
    if (line.empty()) continue;

    size_t tab = line.find('\t');
    size_t sp  = line.find("  ");
    size_t sep = std::string::npos;
    if (tab != std::string::npos) sep = tab;
    else if (sp != std::string::npos) sep = sp;
    if (sep == std::string::npos) continue;

    Counter ctr;
    ctr.name = line.substr(0, sep);
    auto nb = ctr.name.find_first_not_of(" \t");
    if (nb == std::string::npos) continue;
    ctr.name = ctr.name.substr(nb);
    while (!ctr.name.empty() && (ctr.name.back() == ' ' || ctr.name.back() == '\t'))
      ctr.name.pop_back();
    ctr.value = parse_u64(std::string_view(line).substr(sep));
    snap.counters.push_back(std::move(ctr));
  }
  return !snap.counters.empty();
}

// Synthetic busy dual-stack IPv6 host (all 86 kernel counters).
static bool demo_load(Snapshot& snap) {
  struct Row { const char* n; unsigned long long v; };
  static const Row rows[] = {
    {"Ip6InReceives", 12450000}, {"Ip6InHdrErrors", 2}, {"Ip6InTooBigErrors", 11},
    {"Ip6InNoRoutes", 0}, {"Ip6InAddrErrors", 4}, {"Ip6InUnknownProtos", 0},
    {"Ip6InTruncatedPkts", 0}, {"Ip6InDiscards", 412}, {"Ip6InDelivers", 12410000},
    {"Ip6OutForwDatagrams", 880}, {"Ip6OutRequests", 11800000}, {"Ip6OutDiscards", 17},
    {"Ip6OutNoRoutes", 1842}, {"Ip6ReasmTimeout", 0}, {"Ip6ReasmReqds", 240},
    {"Ip6ReasmOKs", 238}, {"Ip6ReasmFails", 2}, {"Ip6FragOKs", 91},
    {"Ip6FragFails", 0}, {"Ip6FragCreates", 182}, {"Ip6InMcastPkts", 22000},
    {"Ip6OutMcastPkts", 18000}, {"Ip6InOctets", 9800000000ull}, {"Ip6OutOctets", 7200000000ull},
    {"Ip6InMcastOctets", 1400000}, {"Ip6OutMcastOctets", 980000},
    {"Ip6InBcastOctets", 0}, {"Ip6OutBcastOctets", 0},
    {"Ip6InNoECTPkts", 12408000}, {"Ip6InECT1Pkts", 0}, {"Ip6InECT0Pkts", 1900},
    {"Ip6InCEPkts", 100}, {"Ip6OutTransmits", 11790000},
    {"Icmp6InMsgs", 18420}, {"Icmp6InErrors", 3}, {"Icmp6OutMsgs", 19110},
    {"Icmp6OutErrors", 1}, {"Icmp6InCsumErrors", 0}, {"Icmp6OutRateLimitHost", 8},
    {"Icmp6InDestUnreachs", 44}, {"Icmp6InPktTooBigs", 11}, {"Icmp6InTimeExcds", 2},
    {"Icmp6InParmProblems", 0}, {"Icmp6InEchos", 620}, {"Icmp6InEchoReplies", 580},
    {"Icmp6InGroupMembQueries", 90}, {"Icmp6InGroupMembResponses", 88},
    {"Icmp6InGroupMembReductions", 4}, {"Icmp6InRouterSolicits", 12},
    {"Icmp6InRouterAdvertisements", 340}, {"Icmp6InNeighborSolicits", 8420},
    {"Icmp6InNeighborAdvertisements", 8210}, {"Icmp6InRedirects", 0},
    {"Icmp6InMLDv2Reports", 76}, {"Icmp6OutDestUnreachs", 31},
    {"Icmp6OutPktTooBigs", 6}, {"Icmp6OutTimeExcds", 0}, {"Icmp6OutParmProblems", 0},
    {"Icmp6OutEchos", 580}, {"Icmp6OutEchoReplies", 620},
    {"Icmp6OutGroupMembQueries", 14}, {"Icmp6OutGroupMembResponses", 90},
    {"Icmp6OutGroupMembReductions", 2}, {"Icmp6OutRouterSolicits", 7},
    {"Icmp6OutRouterAdvertisements", 0}, {"Icmp6OutNeighborSolicits", 8100},
    {"Icmp6OutNeighborAdvertisements", 8510}, {"Icmp6OutRedirects", 0},
    {"Icmp6OutMLDv2Reports", 54},
    {"Udp6InDatagrams", 540000}, {"Udp6NoPorts", 77}, {"Udp6InErrors", 5},
    {"Udp6OutDatagrams", 538000}, {"Udp6RcvbufErrors", 2}, {"Udp6SndbufErrors", 0},
    {"Udp6InCsumErrors", 1}, {"Udp6IgnoredMulti", 14}, {"Udp6MemErrors", 0},
    {"UdpLite6InDatagrams", 0}, {"UdpLite6NoPorts", 0}, {"UdpLite6InErrors", 0},
    {"UdpLite6OutDatagrams", 0}, {"UdpLite6RcvbufErrors", 0},
    {"UdpLite6SndbufErrors", 0}, {"UdpLite6InCsumErrors", 0}, {"UdpLite6MemErrors", 0},
  };
  snap.counters.clear();
  for (const auto& r : rows) snap.counters.push_back(Counter{r.n, r.v});
  return snap.counters.size() == 86;
}

// ─────────────────────────────────────────────────────────────────────────────
// Renderers
// ─────────────────────────────────────────────────────────────────────────────
struct Filters {
  std::string fam;
  std::string dir;
  std::string kind;
  std::string key;
  bool nonzero = false;
  int top = 0;
};

static bool passes(const Counter& c, const Filters& f) {
  if (f.nonzero && !c.nonzero()) return false;
  if (!f.fam.empty()  && fam_name(c.fam()) != f.fam) return false;
  if (!f.dir.empty()  && dir_name(c.dir()) != f.dir) return false;
  if (!f.kind.empty() && kind_name(c.kind()) != f.kind) return false;
  if (!f.key.empty()  && !c.name.starts_with(f.key)) return false;
  return true;
}

static std::string fmt_human(unsigned long long v) {
  char buf[32];
  if (v >= 1000000000ull) {
    std::snprintf(buf, sizeof(buf), "%.2fG", static_cast<double>(v) / 1e9);
  } else if (v >= 1000000ull) {
    std::snprintf(buf, sizeof(buf), "%.2fM", static_cast<double>(v) / 1e6);
  } else if (v >= 1000ull) {
    std::snprintf(buf, sizeof(buf), "%.1fK", static_cast<double>(v) / 1e3);
  } else {
    std::snprintf(buf, sizeof(buf), "%llu", v);
  }
  return buf;
}

static std::vector<const Counter*> select_rows(const Snapshot& snap, const Filters& f) {
  std::vector<const Counter*> rows;
  rows.reserve(snap.counters.size());
  for (const auto& c : snap.counters)
    if (passes(c, f)) rows.push_back(&c);
  if (f.top > 0) {
    std::stable_sort(rows.begin(), rows.end(),
                     [](const Counter* a, const Counter* b) { return a->value > b->value; });
    if (static_cast<int>(rows.size()) > f.top)
      rows.resize(static_cast<std::size_t>(f.top));
  }
  return rows;
}

static void render_snapshot(const Snapshot& snap, const Filters& f, bool quiet_header) {
  if (!quiet_header) {
    std::println(std::cout, "{}-- IPv6 SNMP MIB  /proc/net/snmp6 --{}", C_BOLD, C_RESET);
    std::println(std::cout, "{}ip6 {}  icmp6 {}  udp6 {}  udplite6 {}  nonzero {} / {}{}",
                 C_DIM,
                 snap.fam_count(Fam::Ip6), snap.fam_count(Fam::Icmp6),
                 snap.fam_count(Fam::Udp6), snap.fam_count(Fam::UdpLite6),
                 snap.nonzero_count(), snap.counters.size(), C_RESET);
    std::println(std::cout, "{}in-octets {}  out-octets {}  nd {}  errors {}{}",
                 C_DIM,
                 fmt_human(snap.named("Ip6InOctets")),
                 fmt_human(snap.named("Ip6OutOctets")),
                 snap.kind_total(Kind::Nd),
                 snap.kind_total(Kind::Error),
                 C_RESET);
    std::println(std::cout);
  }

  auto rows = select_rows(snap, f);
  for (const auto* c : rows) {
    std::string col = C_GREEN;
    if (c->kind() == Kind::Error && c->value > 0) col = C_RED;
    else if (c->value >= 1000000ull) col = C_YELLOW;
    else if (c->value > 0) col = C_BLUE;

    int bucket = c->value == 0 ? 0 : (c->value >= 1000000ull ? 3 : (c->value >= 1000ull ? 2 : 1));
    std::string histogram(static_cast<std::size_t>(bucket), '#');
    if (histogram.empty()) histogram = ".";

    std::string shown = (c->kind() == Kind::Octets) ? fmt_human(c->value)
                                                    : std::to_string(c->value);

    std::println(std::cout, "  {}{:<32}{} {} {:>8} {:>8}  {}{:>12}{}  {}{}",
                 C_BOLD, c->name, C_RESET,
                 fam_name(c->fam()),
                 dir_name(c->dir()),
                 kind_name(c->kind()),
                 col, shown, C_RESET,
                 C_DIM, histogram);
  }
  std::println(std::cout, "{}-- {} counters shown --{}", C_DIM, rows.size(), C_RESET);
}

static void render_delta(const Snapshot& prev, const Snapshot& cur, const Filters& f) {
  bool any = false;
  for (const auto& c : cur.counters) {
    if (!passes(c, f)) continue;
    const Counter* p = prev.find(c.name);
    unsigned long long old = p ? p->value : 0;
    if (c.value == old) continue;
    if (!any) {
      std::println(std::cout, "{}-- deltas --{}", C_YELLOW, C_RESET);
      any = true;
    }
    long long d = static_cast<long long>(c.value) - static_cast<long long>(old);
    std::string col = d > 0 ? C_YELLOW : C_GREEN;
    std::println(std::cout, "  {}{:<32}{} {:>+12}{}",
                 col, c.name, C_RESET, d, C_RESET);
  }
  if (any) std::println(std::cout);
}

static std::string json_escape(std::string_view s) {
  std::string o;
  o.reserve(s.size());
  for (char c : s) {
    if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
    else o.push_back(c);
  }
  return o;
}

static void render_json(std::ostream& os, const Snapshot& snap) {
  os << "{\n  \"ts\": " << snap.ts << ",\n  \"source\": \"snmp6\",\n";
  os << "  \"summary\": {\n"
        "    \"count\": " << snap.counters.size() << ",\n"
        "    \"nonzero\": " << snap.nonzero_count() << ",\n"
        "    \"ip6\": " << snap.fam_count(Fam::Ip6) << ",\n"
        "    \"icmp6\": " << snap.fam_count(Fam::Icmp6) << ",\n"
        "    \"udp6\": " << snap.fam_count(Fam::Udp6) << ",\n"
        "    \"udplite6\": " << snap.fam_count(Fam::UdpLite6) << ",\n"
        "    \"in_octets\": " << snap.named("Ip6InOctets") << ",\n"
        "    \"out_octets\": " << snap.named("Ip6OutOctets") << ",\n"
        "    \"errors\": " << snap.kind_total(Kind::Error) << ",\n"
        "    \"nd\": " << snap.kind_total(Kind::Nd) << "\n  },\n";
  os << "  \"counters\": [\n";
  bool first = true;
  for (const auto& c : snap.counters) {
    if (!first) os << ",\n";
    first = false;
    os << "    {\"name\": \"" << json_escape(c.name)
       << "\", \"fam\": \"" << fam_name(c.fam())
       << "\", \"dir\": \"" << dir_name(c.dir())
       << "\", \"kind\": \"" << kind_name(c.kind())
       << "\", \"value\": " << c.value << "}";
  }
  os << "\n  ]\n}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0;
static int g_fail = 0;
static void t_check(bool ok, const char* label) {
  if (ok) {
    ++g_pass;
    std::println(std::cout, "  PASS  {}", label);
  } else {
    ++g_fail;
    std::println(std::cout, "  FAIL  {}", label);
  }
}

static int run_selftest() {
  std::cout << "-- selftest: classification --\n";
  t_check(fam_of("Ip6InReceives") == Fam::Ip6, "Ip6InReceives -> ip6");
  t_check(fam_of("Icmp6InNeighborSolicits") == Fam::Icmp6, "Icmp6InNeighborSolicits -> icmp6");
  t_check(fam_of("Udp6InDatagrams") == Fam::Udp6, "Udp6InDatagrams -> udp6");
  t_check(fam_of("UdpLite6InDatagrams") == Fam::UdpLite6, "UdpLite6 before Udp6 (prefix)");
  t_check(fam_of("Bogus") == Fam::Unknown, "unknown family");
  t_check(dir_of("Ip6ReasmOKs") == Dir::Reasm, "Reasm wins over In");
  t_check(dir_of("Ip6FragCreates") == Dir::Frag, "Frag classified");
  t_check(dir_of("Ip6OutNoRoutes") == Dir::Out, "Out classified");
  t_check(dir_of("Ip6InDelivers") == Dir::In, "In classified");
  t_check(dir_of("Udp6NoPorts") == Dir::Other, "Udp6NoPorts -> other");
  t_check(kind_of("Ip6InOctets") == Kind::Octets, "octets kind");
  t_check(kind_of("Icmp6InNeighborSolicits") == Kind::Nd, "ND kind");
  t_check(kind_of("Icmp6OutMLDv2Reports") == Kind::Mld, "MLD kind");
  t_check(kind_of("Icmp6InEchos") == Kind::Echo, "echo kind");
  t_check(kind_of("Ip6InCEPkts") == Kind::Ecn, "ECN kind");
  t_check(kind_of("Ip6InMcastPkts") == Kind::Mcast, "mcast kind");
  t_check(kind_of("Ip6OutNoRoutes") == Kind::Error, "no-routes is error");
  t_check(kind_of("Udp6NoPorts") == Kind::Error, "no-ports is error");
  t_check(kind_of("Ip6InReceives") == Kind::Traffic, "receives is traffic");

  std::cout << "-- selftest: parser --\n";
  {
    Snapshot s;
    bool ok = load_snapshot(s, "/proc/net/snmp6");
    t_check(ok, "/proc/net/snmp6 opens");
    if (ok) {
      t_check(s.counters.size() == 86, "kernel exposes 86 snmp6 counters");
      t_check(s.fam_count(Fam::Ip6) == 33, "33 Ip6 counters");
      t_check(s.fam_count(Fam::Icmp6) == 36, "36 Icmp6 counters");
      t_check(s.fam_count(Fam::Udp6) == 9, "9 Udp6 counters");
      t_check(s.fam_count(Fam::UdpLite6) == 8, "8 UdpLite6 counters");
      t_check(s.find("Ip6InReceives") != nullptr, "Ip6InReceives present");
      t_check(s.find("Icmp6InNeighborSolicits") != nullptr, "ND solicit present");
      t_check(s.find("UdpLite6MemErrors") != nullptr, "UdpLite6MemErrors present");
    }
  }

  std::cout << "-- selftest: --file with comments (the README workflow) --\n";
  {
    std::string path = "/tmp/snmp6-watch-selftest.table";
    {
      std::ofstream f(path);
      f << "# annotated dump from a dual-stack host\n"
           "Ip6InReceives                   \t1245\n"
           "Ip6InOctets                     \t98000\n"
           "Icmp6InNeighborSolicits         \t42\n"
           "   Udp6NoPorts                  \t7\n"
           "garbage row that should be skipped\n"
           "UdpLite6InDatagrams             \t0\n";
    }
    Snapshot s;
    bool ok = load_snapshot(s, path);
    std::remove(path.c_str());
    t_check(ok, "parse file opens");
    t_check(s.counters.size() == 5, "5 valid rows parsed (garbage+comment skipped)");
    if (s.counters.size() == 5) {
      t_check(s.find("Ip6InReceives")->value == 1245, "Ip6InReceives = 1245");
      t_check(s.find("Ip6InOctets")->value == 98000, "Ip6InOctets = 98000");
      t_check(s.find("Icmp6InNeighborSolicits")->value == 42, "ND = 42");
      t_check(s.find("Udp6NoPorts")->value == 7, "Udp6NoPorts = 7 (trimmed)");
      t_check(s.find("UdpLite6InDatagrams")->value == 0, "UdpLite6 = 0");
    }
  }

  std::cout << "-- selftest: demo --\n";
  {
    Snapshot d;
    bool ok = demo_load(d);
    t_check(ok, "demo loads 86 counters");
    t_check(d.counters.size() == 86, "demo size 86");
    t_check(d.fam_count(Fam::Ip6) == 33, "demo 33 Ip6");
    t_check(d.fam_count(Fam::Icmp6) == 36, "demo 36 Icmp6");
    t_check(d.named("Ip6InReceives") == 12450000, "demo InReceives");
    t_check(d.named("Ip6InOctets") == 9800000000ull, "demo InOctets 9.8G");
    t_check(d.named("Icmp6InNeighborSolicits") == 8420, "demo ND solicits");
    t_check(d.nonzero_count() > 40, "demo has many nonzero");
    t_check(d.kind_total(Kind::Nd) == 8420 + 8210 + 8100 + 8510, "demo ND total");
  }

  std::cout << "-- selftest: filters + --top sort --\n";
  {
    Snapshot d;
    demo_load(d);
    Filters f;
    f.fam = "udp6";
    std::size_t n = 0;
    for (const auto& c : d.counters) if (passes(c, f)) ++n;
    t_check(n == 9, "fam=udp6 keeps 9");
    f.fam.clear();
    f.kind = "nd";
    n = 0;
    for (const auto& c : d.counters) if (passes(c, f)) ++n;
    t_check(n == 4, "kind=nd keeps 4 (in/out NS/NA)");
    f.kind.clear();
    f.dir = "reasm";
    n = 0;
    for (const auto& c : d.counters) if (passes(c, f)) ++n;
    t_check(n == 4, "dir=reasm keeps 4 (Timeout/Reqds/OKs/Fails)");
    f.dir.clear();
    f.key = "UdpLite6";
    n = 0;
    for (const auto& c : d.counters) if (passes(c, f)) ++n;
    t_check(n == 8, "key=UdpLite6 keeps 8");
    f.key.clear();
    f.top = 3;
    auto rows = select_rows(d, f);
    t_check(rows.size() == 3, "--top 3 yields 3 rows");
    bool desc = rows.size() == 3 && rows[0]->value >= rows[1]->value && rows[1]->value >= rows[2]->value;
    t_check(desc, "--top sorts descending (ties allowed)");
    t_check(rows[0]->name == "Ip6InOctets", "largest is Ip6InOctets");
  }

  std::cout << "-- selftest: JSON + --no-color hygiene --\n";
  {
    Snapshot d;
    demo_load(d);
    d.ts = 0;
    std::ostringstream os;
    render_json(os, d);
    std::string j = os.str();
    t_check(j.find("\"Ip6InReceives\"") != std::string::npos, "json contains counter name");
    t_check(j.find("\"fam\": \"ip6\"") != std::string::npos, "json has fam ip6");
    t_check(j.find("\"kind\": \"nd\"") != std::string::npos, "json has kind nd");
    t_check(j.find("\"summary\"") != std::string::npos && j.find("\"counters\"") != std::string::npos,
            "json has summary + counters");
    t_check(j.find("in_octets") != std::string::npos, "json summary in_octets");

    disable_color();
    Filters f;
    std::ostringstream o2;
    std::streambuf* old = std::cout.rdbuf(o2.rdbuf());
    render_snapshot(d, f, false);
    std::cout.rdbuf(old);
    std::string out = o2.str();
    t_check(out.find("\x1b[") == std::string::npos, "no ANSI codes with --no-color");
    enable_color();
  }

  std::cout << "-- selftest: human bytes + watch deltas --\n";
  {
    t_check(fmt_human(9800000000ull).find('G') != std::string::npos, "9.8G human");
    t_check(fmt_human(540000).find('K') != std::string::npos, "540K human");
    t_check(fmt_human(77) == "77", "small stays raw");
    Snapshot a, b;
    demo_load(a);
    demo_load(b);
    b.counters[0].value += 5;  // Ip6InReceives +5
    Filters f;
    std::ostringstream o;
    std::streambuf* old = std::cout.rdbuf(o.rdbuf());
    render_delta(a, b, f);
    std::cout.rdbuf(old);
    std::string out = o.str();
    t_check(out.find("Ip6InReceives") != std::string::npos, "delta emit changed counter");
    t_check(out.find("+5") != std::string::npos, "delta shows +5");
  }

  std::cout << "selftest: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void print_help() {
  std::cout <<
    "snmp6-watch — IPv6 SNMP MIB counters (/proc/net/snmp6)\n"
    "\n"
    "Usage: snmp6-watch [options]\n"
    "\n"
    "  --fam FAM        only family: ip6|icmp6|udp6|udplite6\n"
    "  --dir DIR        only direction: in|out|reasm|frag|other\n"
    "  --kind KIND      only kind: error|octets|nd|mld|echo|ecn|mcast|traffic\n"
    "  --key PREFIX     only counters whose name starts with PREFIX\n"
    "  --nonzero        only counters with value > 0\n"
    "  --top N          top N by value (descending)\n"
    "  --watch N        refresh every N seconds with deltas\n"
    "  --json           machine-readable output\n"
    "  --demo           synthetic busy dual-stack IPv6 host\n"
    "  --file PATH      parse a dump instead of /proc\n"
    "  --no-color       disable ANSI colors\n"
    "  --selftest       run self-tests and exit\n"
    "  -h, --help       this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  bool color_flag = true;
  bool demo = false;
  bool json = false;
  int watch = 0;
  std::string file;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next = [&](std::string_view name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "error: " << name << " requires a value\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };
    if (a == "--fam")       { auto v = next(a); if (!v) return 2; f.fam = *v; }
    else if (a == "--dir")  { auto v = next(a); if (!v) return 2; f.dir = *v; }
    else if (a == "--kind") { auto v = next(a); if (!v) return 2; f.kind = *v; }
    else if (a == "--key")  { auto v = next(a); if (!v) return 2; f.key = *v; }
    else if (a == "--file") { auto v = next(a); if (!v) return 2; file = *v; }
    else if (a == "--top")  { auto v = next(a); if (!v) return 2; f.top = std::atoi(v->c_str()); }
    else if (a == "--watch"){ auto v = next(a); if (!v) return 2; watch = std::atoi(v->c_str()); }
    else if (a == "--nonzero") f.nonzero = true;
    else if (a == "--demo")    demo = true;
    else if (a == "--json")    json = true;
    else if (a == "--no-color") color_flag = false;
    else if (a == "--selftest") return run_selftest();
    else if (a == "-h" || a == "--help") { print_help(); return 0; }
    else { std::cerr << "error: unknown option '" << a << "' (see --help)\n"; return 2; }
  }

  if (!color_flag) disable_color();

  std::string source = file.empty() ? "/proc/net/snmp6" : file;

  if (watch > 0) {
    Snapshot prev;
    bool first = true;
    for (;;) {
      Snapshot cur;
      cur.ts = std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch()).count();
      bool ok = demo ? demo_load(cur) : load_snapshot(cur, source);
      if (!ok) {
        std::cerr << "error: cannot read " << source << "\n";
        return 1;
      }
      if (!first) render_delta(prev, cur, f);
      render_snapshot(cur, f, !first);
      prev = std::move(cur);
      first = false;
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch));
    }
  }

  Snapshot snap;
  snap.ts = std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()).count();
  bool ok = demo ? demo_load(snap) : load_snapshot(snap, source);
  if (!ok) {
    std::cerr << "error: cannot read " << source << "\n";
    return 1;
  }
  if (json) render_json(std::cout, snap);
  else render_snapshot(snap, f, false);
  return 0;
}
