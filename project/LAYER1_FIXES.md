# Layer 1 fixes in this revision

This revision fixes defects in the Layer 1 datapath that were found while re-testing the engine.
None of them reaches an evaluation record: `ComparisonResults/runners/run_c_engine_ours.py`
compiles only the Layer 2 sources it lists, and the shared library it builds is byte-identical
with and without these changes. Most fixes below have a unit test that fails before the fix and
passes after it; some race fixes could only be shown with multi-lcore stress probes, which are not
part of the test suite.

At this revision `meson test` (build with `-Dbuild_tests=true`) runs 23 tests, serially and in
parallel, with no failure and no skip. Before it, the default parallel run reported 7 DPDK tests
as skipped because they collided on the EAL lock, and a serial run failed `syn_proxy_tests` and
`flow_table_tests`.

## Deployment notes

- **Re-warm Layer 2 baselines after deploying.** The HyperLogLog and flow-hash fixes change the
  live values of `unique_src_ips`, `unique_dst_ports`, `unique_flows` and the count-min sketch
  concentration features, and the D12 fix makes `flows_per_sec` on protected-subnet slots count
  new flows (it read 0 before) when `enforce_protected_ips` is off. Baselines learned on the earlier
  values, and any absolute threshold on these features, should be re-learned.
- **Challenged connections lose window scaling, timestamps and SACK.** The SYN-cookie path now
  offers MSS only on both legs, because the proxy does not translate windows or timestamps.
  Connections that are not challenged bypass the proxy and keep every option. Until the first open
  item below is fixed, challenged connections do not work at all.
- **Proxied and bypassed TCP packets now update the flow table**, which costs about 40 ns per
  packet on those paths.
- **Flow entries are reclaimed after a grace period.** Every packet lcore reports a quiescent
  state per burst (`rte_rcu_qsbr`), and a deleted flow's index is reused only after every reader
  has passed one.

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
| Other | `table_full_drops` counted bypassed SYNs; FIN bits survived tuple reuse; re-init left rate state; absent MSS gave 1460 on one path and 536 on the other; `challenge_threshold = 0` meant different things to the validator and the code; `SYN_PROXY_CHALLENGE`/`CONNECT` were unhandled (`-Wswitch`) | each fixed; unit tests cover all but the `-Wswitch` cases, which the build's warning count checks |
| IPv6 | the IPv6 proxy repeated several IPv4 defects (option rule, full-table count, re-init, misaligned option loads) | ported fixes; the IPv6 pipeline itself is unreachable while `validation.ipv6_policy` is 0 |

## flow_table

| Item | Defect | Fix |
|---|---|---|
| MW-flow, AGE, CLEAR | concurrent creates lost or duplicated keys; ageing and clear could delete a key recreated in between and free an index twice | one writer lock per table around every hash write, with re-lookup and recheck under the lock |
| N6 | ageing and eviction reused an entry while another lcore could still hold a pointer to it | deferred reclamation with `rte_rcu_qsbr` |
| D7, R1, R2, R3, N5, blind ACK | emergency eviction removed established bidirectional flows, kept the wrong candidates, raced with handshakes, scored UDP and mid-stream TCP as incomplete handshakes, and protected flows a blind ACK had "completed" | protected class, worst-score tracking, recheck and claim, protection only for a verified handshake |
| D8, R7 | RST validation used a window around a last ACK that was never seen, and the pipeline never called the validator | window only after an ACK; the validator runs at IPv4 and IPv6 Stage 11 |
| PROXY-FLOWS | flows of proxied and bypassed connections were never updated | Stage 9 and the outbound path keep them current |
| D9, D10, D11, R4, R5, N1, N2 | out-of-bounds state name, out-of-bounds stats write from non-EAL threads, false pressure mode, stranded free indices, non-EAL threads sharing lcore 0's cache, soft capacity, missing stats | bounds, clamps, true active counts, bounded caches, ring allocation for non-EAL threads, extendable buckets, full stats sums |
| IPv6 | no emergency eviction, double counting at Stage 11, and the IPv4 allocator and validation defects | ported |
| SEED | fixed hash seed 0 let colliding keys build chains | random seed per table |

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

## Known open items

Present before this revision and not fixed here:

- **`legitimate_ip_add()` whitelists every client that returns a valid SYN cookie, permanently and
  in bypass mode.** Stage 5 then skips every later stage for that source, so the proxied
  connection's later segments go untranslated: as shipped, every connection the proxy challenges
  breaks, its proxy entry is never released, and a source that completes one cookie bypasses the
  protections from then on. A fail-safe fix is to make it a no-op until a legitimate-source table
  with expiry exists.
- **The TCP flag rate table** is written from every lcore without a multi-writer guard and leaks a
  key slot for every expired source, so it eventually refuses every new TCP source.
- `per_ip_features_unregister()` never frees the hash position, so repeated register and
  unregister cycles exhaust the table, and it frees the count-min counters while lock-free readers
  may still use them.
- Layer 1 hashes the IPv6 addresses in the mbuf with misaligned loads (undefined behaviour that
  UBSan reports in `flow_pipeline_tests`); hashing an aligned copy fixes it.
- Other tables lack a multi-writer guard: the IPv4 whitelist in `ip_lists` already loses
  concurrent adds, because `legitimate_ip_add()` writes it from every packet lcore;
  `connection_limits` races when the SYN proxy is disabled; and the uninitialised `src_ip_stats`
  and `spike_detector` modules index their arrays by hash position, which writes out of bounds.

Introduced by this revision:

- A CLOSING proxied entry is deleted after `connect_timeout_ms` (5 s as shipped) of silence, so a
  close whose last segments are delayed longer loses its translation and the client never gets its
  last bytes.
- Once the last ACK retires a proxied entry, a FIN the peer retransmits (because that ACK was lost
  beyond the proxy) goes out untranslated.
- An RST is not sequence-checked before it frees a proxied, bypassed or CONNECTING entry, so a blind
  RST that matches the 4-tuple ends the connection's proxy state.
- Flow tracking of bypassed connections lets a spoofed SYN's flow live about 31 s instead of 5 s,
  because each server SYN-ACK retransmission refreshes it, and in spoofed mode Stage 8b admits any
  segment between the two hosts while that flow exists.
- With deferred reclamation, a reader that stops reporting quiescent states stops index reuse, and
  new flows then go untracked until it resumes.
