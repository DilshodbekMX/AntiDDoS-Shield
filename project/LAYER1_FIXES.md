# Layer 1 fixes in this revision

This revision fixes defects in the Layer 1 datapath that were found while re-testing the engine.
None of them reaches an evaluation record: `ComparisonResults/runners/run_c_engine_ours.py`
compiles only the Layer 2 sources it lists, and the shared library it builds is byte-identical
with and without these changes. Most fixes below have a unit test that fails before the fix and
passes after it. Some race fixes are shown only by multi-lcore stress subtests, which detect a
race only when their worker lcores have free CPUs, or by stress probes that are not part of the
test suite.

At this revision `meson test` (build with `-Dbuild_tests=true`) runs 30 tests, serially and in
parallel, with no failure and no skip. Before it, the default parallel run reported 7 DPDK tests
as skipped because they collided on the EAL lock, and a serial run failed `syn_proxy_tests` and
`flow_table_tests`.

## Deployment notes

- **Re-warm Layer 2 baselines after deploying.** The HyperLogLog and flow-hash fixes change the
  live values of `unique_src_ips`, `unique_dst_ports`, `unique_flows` and the count-min sketch
  concentration features, and the D12 fix makes `flows_per_sec` on protected-subnet slots count
  new flows (it read 0 before) when `enforce_protected_ips` is off. Baselines learned on the earlier
  values, and any absolute threshold on these features, should be re-learned.
- **Challenged connections work, and lose window scaling, timestamps and SACK.** Their segments
  are translated end to end and their entry is released when they close. The SYN-cookie path
  offers MSS only on both legs, because the proxy does not translate windows or timestamps.
  Connections that are not challenged bypass the proxy and keep every option.
- **A valid SYN cookie no longer whitelists its source.** The source is marked in a separate,
  bounded table for 300 s after the cookie, but no decision reads the mark: while the proxy
  challenges, the source's next connections are challenged like any other client's. Letting marked
  sources skip the challenge allowed one source that completed one handshake to fill the SYN proxy
  table. The C config loader reads neither `legitimate_table_size` nor `legitimate_ttl_sec`, which
  the dashboard offers; the engine uses 100000 entries (a table of 131072) and 300 s.
- **Stage 6c no longer drops every SYN of 60 bytes or less.** A SYN with no options, or with MSS
  only as lwIP and other small stacks send it, is counted as an indicator and goes on through the
  pipeline. It is dropped only when its source shows a scan pattern: in a 1 s window, such SYNs to
  ports that cover 8 of 16 port bits, or 100 such SYNs; the source then stays dropped for the rest
  of that window and the next. A flood of such SYNs therefore reaches the SYN proxy and is
  challenged like any SYN flood (on the test VM about 590 ns per SYN against about 260 ns for the
  old Stage 6c drop, plus one SYN-ACK for each up to the proxy's limit of 250,000 SYN-ACKs a
  second, above which the SYNs are dropped). The new setting `signatures.strict_syn_scan`
  (default `false`, read at startup, not offered by the dashboard) restores the old rule. The
  counters are exported through the DPDK telemetry command `/antiddos/signatures`.
- **In spoofed mode a flow admits only what it vouches for.** Stage 8b used to admit any segment
  for which a flow existed. The flow's handshake must now be verified, or the server must have sent
  its own SYN or an ACK on it, or the segment must be the handshake ACK itself. A connection first
  seen mid-stream (after a restart, or once its flow aged) is admitted once the server has sent
  data or an ACK on it; until then its client's segments pass only if a SYN proxy entry vouches for
  them.
- **RSTs outside the window are dropped.** For a connection the SYN proxy holds, a client RST
  outside every window the server can have is dropped and counted as spoofed TCP
  (`l1_drop_spoofed_tcp`). An RST in the window but not at the receiver's next sequence is
  forwarded, and the entry stays until an exact RST or a timeout ends it.
- **Proxied connections linger after a close.** A closing entry is kept up to 60 s without a
  segment, and a closed one 5 s (a TIME_WAIT that still translates retransmissions), both capped
  at the idle timeout. `connections_active` includes closed entries until they are freed, so the
  table needs room for 5 s of closes.
- **Proxied and bypassed TCP packets now update the flow table**, which costs about 40 ns per
  packet on those paths.
- **Flow entries are reclaimed after a grace period.** Every packet lcore reports a quiescent
  state per burst (`rte_rcu_qsbr`), and a deleted flow's index is reused only after every reader
  has passed one. A reader that has not reported for 3 to 4 s is logged at WARNING with its lcore
  id and counted, and at NOTICE when it reports again. While a reader is stalled, aging and
  emergency eviction pause and no deleted entry is reused: once the free entries run out, new flows
  go untracked, and Stage 11 passes them on to Stage 12 untracked instead of applying the emergency
  drop. Watch for that warning.
- **The shared tables fail open when full.** A new source that finds the TCP flag rate table full
  is accepted untracked and counted (`table_full`), as `connection_limits` already did. The
  shipped engine does not initialise the TCP flag rate table (see the open items).

## syn_proxy

| Item | Defect | Fix |
|---|---|---|
| S5 | `syn_proxy_quick_cookie_check()` had no prototype; the implicit `int` return carried hash residue, so in spoofed mode Stage 8b passed almost every invalid cookie after the 11th failure | prototype in `syn_proxy.h` |
| D1 | BYPASSED entries were never freed, so the table filled and valid-cookie ACKs were dropped under attack | released on RST, on the ACK after both FINs, and by idle ageing |
| PCLOSE | a proxied entry was not released when the client closed or aborted with ACK set (the ACK branch ran first), so a challenged flood filled the table | RST and FIN handled before the ACK branch; release on the segment after both FINs are acknowledged |
| D2 | NULL dereference of the Layer 1 config when a per-IP snapshot arrived before a config was active | NULL-safe circuit-breaker checks |
| D3 | `anomaly_is_spoofed_mode()` and seven functions called by `layer1_factory_reset()` were used through implicit declarations, five of them defined nowhere | prototypes for those that exist; the five calls to undefined functions removed from `layer1_factory_reset()`, which now logs each skipped subsystem |
| D4 | an invalid cookie with ACK 0 was counted twice | counted once |
| D5 | half-open counts survived a re-initialisation | reset in init and in clear-all |
| D6 | the cookie path offered the server options the client never offered and told the client a window scale the server leg did not use | MSS only on both legs |
| D15 | in spoofed mode Stage 8b dropped every later segment of SYN-proxied connections, which have no flow entry | Stage 8b admits live proxied entries, and bypassed entries only after a verified handshake (ACK of the server ISN + 1) |
| MW-syn, ABA | concurrent adds from several lcores could corrupt the hash; a stale free could release a reused slot | `MULTI_WRITER_ADD` with the pool sized by `rte_hash_max_key_id()`; a 32-bit control word with a generation, every transition by compare-and-swap |
| CLAIM-RACE | a slot could be claimed after its key had been retired | the claim holds only while the key still maps to the slot |
| Cleanup | at most 256 deletions per pass, timeouts counted for undeleted entries, double decrement of the active count, unbounded pass time | deletion and scan budgets with a carried-over iterator; counters only for real deletions; one retire per entry |
| LEGIT | `legitimate_ip_add()` whitelisted every client that returned a valid SYN cookie, permanently and in bypass mode: Stage 5 then skipped every later stage for it, so the segments of a challenged connection went out untranslated (every challenged connection broke and its entry was never released), the source escaped every protection from then on, and every packet lcore wrote the whitelist | a separate legitimate-source table: fixed-size sets, a hash with a random key, compare-and-swap writes, and a 300 s TTL from the cookie that the source's own SYNs never renew. Nothing is whitelisted, and no decision reads the mark: exempting marked sources from the challenge let one source fill the table with bypassed entries, so that other clients' valid cookies were dropped |
| CLOSING-TIMEOUT | a closing proxied entry was deleted after `connect_timeout_ms` (5 s as shipped) without a segment, so a close whose last segments were retransmitted later lost its translation and the client never got its last bytes | a closing entry waits 60 s, capped at the idle timeout |
| FIN-AFTER-RELEASE | once the last ACK retired a proxied entry, a FIN that the peer retransmitted (because that ACK was lost beyond the proxy) went out untranslated | the last ACK moves the entry to CLOSED, a 5 s TIME_WAIT capped at the idle timeout that still translates; the close is counted once, and a new SYN on the 4-tuple ends the TIME_WAIT at once |
| BLIND-RST | any RST that matched the 4-tuple freed a proxied, CONNECTING or bypassed entry, so a blind RST made the proxy forget the connection | RSTs are checked against the receiver's next sequence (RFC 5961): an exact RST ends the entry, an RST in the window is forwarded and the entry stays, a client RST outside every window is dropped as spoofed TCP, and the server's RSTs are always forwarded once the server leg is established (while the proxy waits on the server, one ends the entry only if it acknowledges the proxy's SYN, and is not forwarded); an RST that does not end the entry does not tear its flow down either |
| Other | `table_full_drops` counted bypassed SYNs; FIN bits survived tuple reuse; re-init left rate state; absent MSS gave 1460 on one path and 536 on the other; `challenge_threshold = 0` meant different things to the validator and the code; `SYN_PROXY_CHALLENGE`/`CONNECT` were unhandled (`-Wswitch`) | each fixed; unit tests cover all but the `-Wswitch` cases, which the build's warning count checks |
| IPv6 | the IPv6 proxy repeated several IPv4 defects (option rule, full-table count, re-init, misaligned option loads) | ported fixes; the IPv6 pipeline itself is unreachable while `validation.ipv6_policy` is 0 |

## ip_lists

| Item | Defect | Fix |
|---|---|---|
| IP_LISTS | the whitelist, blacklist and protected hashes take one writer at a time, but nothing serialised their writers, and `legitimate_ip_add()` wrote the whitelist from every packet lcore, so concurrent adds lost keys; the CIDR LPM, the protected-subnet side table and the per-IP feature registration had no writer locking either | one writer lock for every IPv4 list writer, all of them on the control path; readers stay lock-free, and no packet lcore writes a list |

## flow_table

| Item | Defect | Fix |
|---|---|---|
| MW-flow, AGE, CLEAR | concurrent creates lost or duplicated keys; ageing and clear could delete a key recreated in between and free an index twice | one writer lock per table around every hash write, with re-lookup and recheck under the lock |
| N6 | ageing and eviction reused an entry while another lcore could still hold a pointer to it | deferred reclamation with `rte_rcu_qsbr` |
| QSBR-STALL | a reader that stopped reporting quiescent states blocked index reuse unnoticed, while ageing and eviction kept deleting into a limbo that could not drain | a stalled reader is found 3 to 4 s after its last report, logged at WARNING with its lcore id and counted; while it is stalled ageing and emergency eviction pause, and no entry it may hold is reused |
| STALL-DROP | while a reader was stalled, creates failed once the free entries ran out, and Stage 11 then applied the emergency drop (90% of unknown sources as shipped) because of an internal fault | Stage 11 applies no emergency drop while a reader is stalled; the packet goes on untracked to Stage 12, as the share not dropped does |
| D7, R1, R2, R3, N5, blind ACK | emergency eviction removed established bidirectional flows, kept the wrong candidates, raced with handshakes, scored UDP and mid-stream TCP as incomplete handshakes, and protected flows a blind ACK had "completed" | protected class, worst-score tracking, recheck and claim, protection only for a verified handshake |
| D8, R7 | RST validation used a window around a last ACK that was never seen, and the pipeline never called the validator | window only after an ACK; the validator runs at IPv4 and IPv6 Stage 11 |
| PROXY-FLOWS | flows of proxied and bypassed connections were never updated | Stage 9 and the outbound path keep them current |
| SPOOF-FLOW | a server's SYN-ACK retransmissions kept the flow of a spoofed SYN alive for about 31 s, and in spoofed mode Stage 8b admitted any segment between the two hosts while that flow existed | a SYN-ACK does not refresh a flow whose handshake is not verified, and the proxy's outbound path no longer recreates it; Stage 8b admits by flow only a verified handshake, a destination that has sent its own SYN or an ACK without SYN or RST, or the handshake ACK itself (IPv4 and IPv6) |
| D9, D10, D11, R4, R5, N1, N2 | out-of-bounds state name, out-of-bounds stats write from non-EAL threads, false pressure mode, stranded free indices, non-EAL threads sharing lcore 0's cache, soft capacity, missing stats | bounds, clamps, true active counts, bounded caches, ring allocation for non-EAL threads, extendable buckets, full stats sums |
| IPv6 | no emergency eviction, double counting at Stage 11, and the IPv4 allocator and validation defects | ported |
| IPV6-ALIGN | the IPv6 path hashed the addresses in place in the mbuf (misaligned loads, undefined behaviour that UBSan reported in `flow_pipeline_tests`) | hashed from aligned copies, with the same values; the IPv6 flow key is hashed from a copy too |
| SEED | fixed hash seed 0 let colliding keys build chains | random seed per table |

## Other shared tables

| Item | Defect | Fix |
|---|---|---|
| TCPFLAG | the TCP flag rate table (Stage 9b) was written from every lcore without a writer guard, so concurrent adds lost sources; every expired source leaked a key position, so once `max_entries` (40,000 as shipped) distinct sources had been seen every new source was dropped; a source that found the table full was dropped; and two clock comparisons wrapped (the cleanup deleted sources refreshed during its pass, and a refill by another lcore restored a full bucket). The shipped engine never initialises this table (see the open items), so in the shipped engine all of this was latent | a writer lock with a re-lookup; positions released after the readers' grace period, with a published flag per bucket; a new source that finds the table full is accepted untracked and counted; clock guards |
| PERIP-UNREG | `per_ip_features_unregister()` never released the hash position, so registration failed after 2 x `max_ips` cycles, and it freed the count-min counters while lock-free readers could still use them; the stats thread's walks raced unregistration | slot, counters and position released after the readers' grace period; readers load the counter pointer once; one control lock for registration, unregistration and the stats walks; a registration waits at most 50 ms for a slot |
| CONNLIM | `connection_limits` (Stage 10 with the SYN proxy off) lost concurrent first connections, wiped counts on a racing add, reused a deleted tracker under readers, and two clock comparisons wrapped | a writer lock with a re-lookup, an additive setup, deferred tracker reuse, clock guards |
| DEAD-MODULES | `src_ip_stats` wrote past its array, faulted on non-EAL threads, freed entries under readers, and its clock wrapped so that its 300 s expiry never fired; `spike_detector` indexed its pool by hash position and freed windows under readers. The shipped engine initialises neither | `src_ip_stats`: no per-lcore slot caches, entries sized by `rte_hash_max_key_id()`, a writer lock and a control lock, deferred release, and a clock that does not wrap; `spike_detector`: its pool indexed by the slot stored with the key, a control lock, deferred release and a bounded wait for a slot; nothing was wired |

## Signatures (Stage 6c)

| Item | Defect | Fix |
|---|---|---|
| SYN-SCAN | Stage 6c dropped every SYN-only frame of 60 bytes or less (no options, or MSS only) as a scan, on frame size alone, so clients of small stacks such as lwIP could not connect | such a frame is an indicator, counted and exported through `/antiddos/signatures`; it is dropped only when its source shows a scan pattern in a fixed per-source tracker (8 of 16 port bits, or 100 such SYNs, in a 1 s window, carried one window), or when `signatures.strict_syn_scan` is set |

## Telemetry and parser

| Item | Defect | Fix |
|---|---|---|
| HLL | `rho` counted the index bits, so every register was at least 15 and estimates exploded above about 20,000 keys (100,000 random keys read as more than 5 million); CRC-based hashes were linear | correct `rho`, an `fmix64` finalizer, and Ertl's improved estimator; accuracy tested from 1 to 1,000,000 keys |
| FLOWHASH | `parse_packet()` hashed four stale stack bytes in place of the protocol (strict-aliasing miscompile at `-O2`/`-O3`), so TCP and UDP between two hosts shared a hash and the value changed between runs | strict-aliasing-safe word reads; tested against a bytewise CRC32-C |
| D12 | new flows to an address covered only by a protected subnet were not counted on the subnet slot | the counting path resolves the same track key as the packet path; with the shipped `enforce_protected_ips = true`, Stage 4d drops such traffic earlier, so the fix matters only with enforcement off |
| IPv6 HLL | structured IPv6 source sets collapsed to a few keys, and IPv6 per-IP sketches were never reset | full-address hashing and per-window resets |
| SIMD | `simd_hll_batch_add()` and `simd_hll_harmonic_sum()`, which had no caller, repeated the HLL defects | removed; `tests/unit/test_simd_utils.c` fails to compile if either returns |

## Tests

The DPDK unit tests now pass `--no-shconf --no-telemetry` and count their arguments, so they no
longer collide when meson runs them in parallel. `test_innovation_gate` is registered. Failing
subtests now clean up their module, so one failure no longer cascades into the next subtest.

Seven test binaries are new: `ip_lists_tests`, `signatures_tests`, `tcp_flag_rate_tests`,
`per_ip_unregister_tests`, `connection_limits_tests`, `src_ip_stats_tests` and
`spike_detector_tests`. `flow_pipeline_tests` drives through `layer1_process_packet_ex()` the
close of a challenged connection, blind RSTs, a source that returned a valid cookie, spoofed-mode
admission by flow, SYNs of 60 bytes or less, and a full flow table with a stalled reader. Their
stress subtests detect a race only when their worker lcores have free CPUs; the deterministic seam
subtests are the gates.

## Known open items

Present before this revision and not fixed here:

- **The C config loader ignores the `tcp_flag_rate` and `tcp_abuse` sections**, so the shipped
  engine never initialises the TCP flag rate table, and Stage 9b accepts every packet; the backend
  still offers both sections for editing. Before the loader reads them, the full-table path needs
  a check that takes no lock: once the table is full, every packet of an untracked source takes
  the table's writer lock (6 to 9 times the earlier cost per packet with 3 lcores in a probe).
- **`connection_limits_update()` has no caller**, so `active_connections` never drops and no
  tracker expires: with the SYN proxy off, once `max_ips` (100,000) distinct sources have been
  seen, every new source goes untracked.
- **If the proxy's ACK to the server's SYN-ACK is lost**, the proxy drops the server's SYN-ACK
  retransmissions and never sends that ACK again, so a challenged connection to a server that
  speaks first (SMTP, SSH, FTP) hangs until the server gives up.
- **Stage 6c's attack-tool rules still drop on the shape of one packet**: every UDP frame of
  exactly 1024 bytes from a source port above 49152 (4001), UDP to port 53 in a 60-byte frame
  (4010), and every GRE packet (4020), although the shipped `other_protocols` filter allows
  protocol 47; rule 2003 can never match a real frame. The dashboard's per-signature toggles are
  never read by the engine, and the signature settings apply at startup only.
- **A blind sender can still make a planted flow vouch at Stage 8b.** A spoofed SYN let through
  in calm conditions opens a half-open connection on the server, and a segment without ACK
  outside its window (PSH only, say) draws a pure ACK from a Linux server (`tcp_check_req()`;
  checked on Linux 6.8); an ACK without SYN or RST makes the flow vouch (SPOOF-FLOW). One more
  blind segment per spoofed source, sent before spoofed mode starts, therefore admits every
  later segment from that source to the server, on any port, and those segments keep the flow
  alive. This revision narrows the hole (a planted flow alone admits nothing) but does not
  close it.
- `ip_protected_clear()` resets the protected hash without unregistering the per-IP slots.
- In the shared tables, the TCP flag token buckets, the per-IP window roll and the spike
  detector's per-lcore counts are updated without atomics across lcores (a lost or double count),
  and the `connection_limits` and `spike_detector` lookups take a read lock that a preempted writer
  holds off.
- `layer1_init()` gives the IPv6 lists no LPM6 rules, so the IPv6 whitelist, blacklist and
  protected lists never initialise. This is latent while `validation.ipv6_policy` is 0, as is the
  IPv6 SYN proxy, which has none of the RST validation and close lingers above.

Introduced by this revision:

- **A stalled flow table reader still stops index reuse**, by design: no entry it may hold is
  reused. It is found 3 to 4 s after its last report; until it reports again, new flows go
  untracked once the free entries run out, and the stall shows only in the log and in the table's
  getters, not in telemetry. A stall of the maintenance lcore itself is not detected.
- **A returning client loses its TCP options to the challenge.** While the proxy challenges, each
  new connection of a client that has already returned a valid cookie is challenged again (MSS
  only). Exempting such clients needs a bound per source first, for example a cap on its live
  bypassed entries, granted only while the table has room and never in spoofed mode.
- **RST validation leaves some aborts inexact.** An RST past the receiver's last ACK (a peer that
  resets with its own data unacknowledged, or a server abort right after a retransmission) is
  forwarded, and the entry stays until an exact RST or the idle timeout (300 s); a new SYN on that
  proxied 4-tuple is dropped until then. While the proxy waits on the server, a client RST that is
  not exact is dropped. The recorded ACK numbers follow the latest segment, so ACK reordering, or a
  stale holder of a reused entry, can make a legitimate RST look out of window; the peer's next
  segment then draws an exact one.
- **The close lingers hold entries longer.** A new SYN on a closing 4-tuple is dropped for up to
  60 s, and each closed entry holds table room for 5 s.
- **In spoofed mode with the SYN proxy off for a destination**, a handshake slower than
  `syn_timeout_sec` loses its half-open flow (a SYN-ACK no longer refreshes it), and its ACK is
  then dropped as spoofed; two parallel handshakes between the same hosts can briefly delay the
  earlier one's ACK.
- **Stage 6c's scan tracker can be framed or blinded.** Spoofed minimal SYNs to 8 ports a second
  under a victim's address keep that address's minimal SYNs dropped; a source that sends more than
  100 minimal SYNs a second (a NAT in front of many small-stack clients, a reconnect storm) has all
  of them dropped from its second window on; and the tracker's hash is unseeded, so a chosen decoy
  can leave a scanner untracked.
- Test gaps: the `strict_syn_scan` pin checks the configuration helper rather than
  `layer1_init()` itself, nothing asserts the `/antiddos/signatures` reply, some delete-time
  rechecks in the shared tables survive their mutations, and three `src_ip_stats` subtests fail
  on a host whose TSC has counted less than 300 s (one booted under five minutes ago).
