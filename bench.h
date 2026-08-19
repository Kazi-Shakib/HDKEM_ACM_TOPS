/*
 * bench.h — measurement harness for HDKEM
 *
 * Design goals (each addresses a defect in the previous driver):
 *   - No single-shot timings. Every figure is a distribution.
 *   - Auto-tuned inner batching so that per-window duration >> timer overhead.
 *     Sub-microsecond primitives (HKDF, X25519) cannot be measured with one
 *     clock_gettime pair; the syscall/vDSO overhead is the same order as the
 *     operation.
 *   - True retired CPU cycles via perf_event_open, not wall-time * nominal GHz.
 *     Frequency scaling makes the derived figure wrong by 10-40% on laptops
 *     and by more on the Pi.
 *   - Explicit COLD (first-call, cache-cold) vs HOT (steady-state) reporting.
 *     A handshake in deployment is a cold path; a microbenchmark loop is not.
 *     Reporting only one of the two invites a reviewer objection either way.
 *   - Non-parametric median CI, because Falcon/Gandalf signing is rejection-
 *     sampled and its latency distribution is right-skewed, not Gaussian.
 *     Mean +- stddev is the wrong summary for it.
 */

#ifndef HDKEM_BENCH_H
#define HDKEM_BENCH_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define BENCH_DEFAULT_OUTER   1000   /* windows per operation                 */
#define BENCH_MIN_WINDOW_NS   200000 /* 200 us: auto-tune inner reps to this  */
#define BENCH_WARMUP_WINDOWS  20     /* discarded before measurement          */

/* Operation under test. ctx is passed through untouched. Return value is
 * accumulated into a volatile sink so the optimiser cannot elide the call. */
typedef uint64_t (*bench_fn)(void *ctx);

typedef struct {
    const char *name;
    const char *role;        /* "Srv" | "Cli" | "-"                          */

    size_t   n;              /* number of windows kept                        */
    size_t   inner;          /* reps per window (auto-tuned)                  */

    /* per-operation nanoseconds, steady state */
    double   ns_min, ns_p05, ns_median, ns_p95, ns_max, ns_mean, ns_sd, ns_mad;
    double   ns_ci_lo, ns_ci_hi;   /* 95% CI of the median (order statistic)  */

    /* per-operation retired core cycles, steady state (0 if unavailable) */
    double   cyc_median, cyc_p95, cyc_mean;
    int      cycles_valid;

    /* first invocation on a cold instruction/data cache, single sample */
    double   ns_cold;

    double  *samples;        /* ns per op, ascending; owned by caller         */
} bench_result_t;

/* ---- lifecycle ---- */
int      bench_init(void);          /* opens perf counter; 0 ok, -1 no cycles */
void     bench_shutdown(void);
int      bench_cycles_available(void);
double   bench_timer_overhead_ns(void);
double   bench_tsc_ghz(void);       /* measured, for reference only           */

/* ---- measurement ---- */
/* cold_fn may be NULL. If given, it is invoked exactly once, before any
 * warm-up, to capture the cold-cache latency of the same operation. */
bench_result_t bench_run(const char *name, const char *role,
                         bench_fn fn, void *ctx,
                         size_t outer, bench_fn cold_fn, void *cold_ctx);

void bench_free(bench_result_t *r);

/* ---- reporting ---- */
void bench_print_header(void);
void bench_print(const bench_result_t *r);
void bench_csv_header(FILE *f);
void bench_csv_row(FILE *f, const bench_result_t *r);

/* Environment provenance: CPU model, governor, current MHz, ASLR, turbo,
 * isolation. Anything a reviewer needs in order to believe the numbers. */
void bench_print_environment(FILE *f);

/* keeps the optimiser honest */
extern volatile uint64_t bench_sink;

#endif /* HDKEM_BENCH_H */
