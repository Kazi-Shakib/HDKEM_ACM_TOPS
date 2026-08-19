#define _GNU_SOURCE
#include "bench.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>

#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#endif

volatile uint64_t bench_sink = 0;

static int    g_perf_fd      = -1;
static double g_timer_ns     = 0.0;
static double g_tsc_ghz      = 0.0;

/* ------------------------------------------------------------------ clock */

static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ---------------------------------------------------------- perf counters */

#if defined(__linux__)
static long perf_open(struct perf_event_attr *a, pid_t pid, int cpu,
                      int grp, unsigned long flags)
{
    return syscall(__NR_perf_event_open, a, pid, cpu, grp, flags);
}
#endif

int bench_init(void)
{
    /* timer overhead: subtracted from every window */
    {
        const int N = 20000;
        uint64_t t0 = now_ns();
        for (int i = 0; i < N; i++) bench_sink += now_ns();
        uint64_t t1 = now_ns();
        g_timer_ns = (double)(t1 - t0) / N;
    }

    /* TSC rate, informational only (never used to convert times to cycles) */
#if defined(__x86_64__)
    {
        extern uint64_t __rdtsc(void);
        uint64_t c0, c1, t0, t1;
        struct timespec sl = { 0, 50000000L }; /* 50 ms */
        t0 = now_ns(); c0 = __builtin_ia32_rdtsc();
        nanosleep(&sl, NULL);
        c1 = __builtin_ia32_rdtsc(); t1 = now_ns();
        g_tsc_ghz = (double)(c1 - c0) / (double)(t1 - t0);
    }
#endif

#if defined(__linux__)
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof pe);
    pe.type           = PERF_TYPE_HARDWARE;
    pe.size           = sizeof pe;
    pe.config         = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled       = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv     = 1;

    g_perf_fd = (int)perf_open(&pe, 0, -1, -1, 0);
    if (g_perf_fd < 0) {
        fprintf(stderr,
            "[bench] hardware cycle counter unavailable (%s).\n"
            "        Cycle columns will be omitted rather than derived from\n"
            "        wall time x nominal clock. To enable:\n"
            "          sudo sysctl -w kernel.perf_event_paranoid=1\n",
            strerror(errno));
        return -1;
    }
#endif
    return 0;
}

void bench_shutdown(void)
{
    if (g_perf_fd >= 0) { close(g_perf_fd); g_perf_fd = -1; }
}

int    bench_cycles_available(void) { return g_perf_fd >= 0; }
double bench_timer_overhead_ns(void) { return g_timer_ns; }
double bench_tsc_ghz(void) { return g_tsc_ghz; }

static inline void cyc_start(void)
{
#if defined(__linux__)
    if (g_perf_fd >= 0) {
        ioctl(g_perf_fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(g_perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    }
#endif
}

static inline uint64_t cyc_stop(void)
{
#if defined(__linux__)
    if (g_perf_fd >= 0) {
        uint64_t v = 0;
        ioctl(g_perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        if (read(g_perf_fd, &v, sizeof v) == (ssize_t)sizeof v) return v;
    }
#endif
    return 0;
}

/* --------------------------------------------------------------- cache ops */

/* Evict L1/L2/L3 by streaming a buffer larger than the LLC. Used only for the
 * cold-start sample; not inside the steady-state loop. */
static void flush_caches(void)
{
    const size_t sz = 64u << 20; /* 64 MiB */
    static uint8_t *scratch = NULL;
    if (!scratch) scratch = malloc(sz);
    if (!scratch) return;
    for (size_t i = 0; i < sz; i += 64) scratch[i] = (uint8_t)(i ^ 0x5A);
    for (size_t i = 0; i < sz; i += 64) bench_sink += scratch[i];
#if defined(__x86_64__)
    __builtin_ia32_mfence();
#endif
}

/* ---------------------------------------------------------------- sorting */

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double quantile_sorted(const double *v, size_t n, double q)
{
    if (n == 0) return 0.0;
    if (n == 1) return v[0];
    double pos = q * (double)(n - 1);
    size_t lo  = (size_t)pos;
    double fr  = pos - (double)lo;
    if (lo + 1 >= n) return v[n - 1];
    return v[lo] * (1.0 - fr) + v[lo + 1] * fr;
}

/* 95% CI for the median from order statistics (binomial / normal approx).
 * Distribution-free, which matters because rejection-sampled signing is not
 * remotely normal. */
static void median_ci(const double *v, size_t n, double *lo, double *hi)
{
    if (n < 10) { *lo = v[0]; *hi = v[n - 1]; return; }
    double c  = 1.96 * sqrt((double)n) / 2.0;
    double dl = floor((double)n / 2.0 - c);
    double dh = ceil ((double)n / 2.0 + c);
    size_t il = (dl < 0) ? 0 : (size_t)dl;
    size_t ih = (dh >= (double)n) ? n - 1 : (size_t)dh;
    *lo = v[il];
    *hi = v[ih];
}

/* ------------------------------------------------------------ measurement */

/* Choose inner reps so one window lasts >= BENCH_MIN_WINDOW_NS. This is what
 * makes sub-microsecond primitives measurable at all: with inner=1 the
 * clock_gettime pair (~%.0f ns) dominates a 2 us HKDF call. */
static size_t tune_inner(bench_fn fn, void *ctx)
{
    size_t inner = 1;
    for (;;) {
        uint64_t t0 = now_ns();
        for (size_t i = 0; i < inner; i++) bench_sink += fn(ctx);
        uint64_t dt = now_ns() - t0;
        if (dt >= BENCH_MIN_WINDOW_NS) break;
        if (inner >= (1u << 22)) break;
        size_t next = (dt == 0) ? inner * 8
                                : (size_t)((double)inner *
                                   ((double)BENCH_MIN_WINDOW_NS / (double)dt) * 1.3) + 1;
        inner = (next <= inner) ? inner * 2 : next;
    }
    return inner;
}

bench_result_t bench_run(const char *name, const char *role,
                         bench_fn fn, void *ctx,
                         size_t outer, bench_fn cold_fn, void *cold_ctx)
{
    bench_result_t r;
    memset(&r, 0, sizeof r);
    r.name = name;
    r.role = role;

    if (outer == 0) outer = BENCH_DEFAULT_OUTER;

    /* ---- cold sample: one call, caches evicted, before any warm-up ---- */
    if (cold_fn) {
        flush_caches();
        uint64_t t0 = now_ns();
        bench_sink += cold_fn(cold_ctx);
        r.ns_cold = (double)(now_ns() - t0) - g_timer_ns;
        if (r.ns_cold < 0) r.ns_cold = 0;
    }

    /* ---- warm-up ---- */
    size_t inner = tune_inner(fn, ctx);
    r.inner = inner;
    for (size_t w = 0; w < BENCH_WARMUP_WINDOWS; w++)
        for (size_t i = 0; i < inner; i++) bench_sink += fn(ctx);

    /* ---- measured windows ---- */
    double *ns  = malloc(outer * sizeof *ns);
    double *cyc = malloc(outer * sizeof *cyc);
    if (!ns || !cyc) { free(ns); free(cyc); return r; }

    int have_cyc = bench_cycles_available();

    for (size_t w = 0; w < outer; w++) {
        if (have_cyc) cyc_start();
        uint64_t t0 = now_ns();
        for (size_t i = 0; i < inner; i++) bench_sink += fn(ctx);
        uint64_t t1 = now_ns();
        uint64_t c  = have_cyc ? cyc_stop() : 0;

        double per = ((double)(t1 - t0) - g_timer_ns) / (double)inner;
        ns[w]  = per > 0 ? per : 0.0;
        cyc[w] = have_cyc ? (double)c / (double)inner : 0.0;
    }

    /* ---- summarise ---- */
    double mean = 0.0;
    for (size_t i = 0; i < outer; i++) mean += ns[i];
    mean /= (double)outer;

    double var = 0.0;
    for (size_t i = 0; i < outer; i++) { double d = ns[i] - mean; var += d * d; }
    var /= (double)(outer > 1 ? outer - 1 : 1);

    qsort(ns,  outer, sizeof *ns,  cmp_double);
    qsort(cyc, outer, sizeof *cyc, cmp_double);

    r.n         = outer;
    r.ns_mean   = mean;
    r.ns_sd     = sqrt(var);
    r.ns_min    = ns[0];
    r.ns_max    = ns[outer - 1];
    r.ns_p05    = quantile_sorted(ns, outer, 0.05);
    r.ns_median = quantile_sorted(ns, outer, 0.50);
    r.ns_p95    = quantile_sorted(ns, outer, 0.95);
    median_ci(ns, outer, &r.ns_ci_lo, &r.ns_ci_hi);

    {   /* median absolute deviation: robust spread, unlike sd */
        double *dev = malloc(outer * sizeof *dev);
        if (dev) {
            for (size_t i = 0; i < outer; i++) dev[i] = fabs(ns[i] - r.ns_median);
            qsort(dev, outer, sizeof *dev, cmp_double);
            r.ns_mad = quantile_sorted(dev, outer, 0.50);
            free(dev);
        }
    }

    if (have_cyc) {
        double cm = 0.0;
        for (size_t i = 0; i < outer; i++) cm += cyc[i];
        r.cyc_mean   = cm / (double)outer;
        r.cyc_median = quantile_sorted(cyc, outer, 0.50);
        r.cyc_p95    = quantile_sorted(cyc, outer, 0.95);
        r.cycles_valid = 1;
    }

    r.samples = ns;
    free(cyc);
    return r;
}

void bench_free(bench_result_t *r)
{
    if (r && r->samples) { free(r->samples); r->samples = NULL; }
}

/* ------------------------------------------------------------- reporting */

void bench_print_header(void)
{
    printf("%-28s %-4s %8s %9s %9s %9s %9s %10s %8s\n",
           "Operation", "Role", "n",
           "med(ms)", "p05(ms)", "p95(ms)", "MAD(ms)", "Mcyc(med)", "cold(ms)");
    printf("%-28s %-4s %8s %9s %9s %9s %9s %10s %8s\n",
           "----------------------------", "----", "--------",
           "---------", "---------", "---------", "---------",
           "----------", "--------");
}

void bench_print(const bench_result_t *r)
{
    printf("%-28s %-4s %8zu %9.4f %9.4f %9.4f %9.4f ",
           r->name, r->role, r->n,
           r->ns_median / 1e6, r->ns_p05 / 1e6,
           r->ns_p95 / 1e6, r->ns_mad / 1e6);
    if (r->cycles_valid) printf("%10.4f ", r->cyc_median / 1e6);
    else                 printf("%10s ", "n/a");
    if (r->ns_cold > 0)  printf("%8.4f\n", r->ns_cold / 1e6);
    else                 printf("%8s\n", "-");
}

void bench_csv_header(FILE *f)
{
    fprintf(f, "operation,role,n,inner,"
               "ns_median,ns_p05,ns_p95,ns_mean,ns_sd,ns_mad,"
               "ns_ci_lo,ns_ci_hi,ns_min,ns_max,ns_cold,"
               "cycles_median,cycles_p95,cycles_mean,cycles_valid\n");
}

void bench_csv_row(FILE *f, const bench_result_t *r)
{
    fprintf(f, "%s,%s,%zu,%zu,"
               "%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,"
               "%.3f,%.3f,%.3f,%.3f,%.3f,"
               "%.1f,%.1f,%.1f,%d\n",
            r->name, r->role, r->n, r->inner,
            r->ns_median, r->ns_p05, r->ns_p95, r->ns_mean, r->ns_sd, r->ns_mad,
            r->ns_ci_lo, r->ns_ci_hi, r->ns_min, r->ns_max, r->ns_cold,
            r->cyc_median, r->cyc_p95, r->cyc_mean, r->cycles_valid);
}

/* ----------------------------------------------------------- provenance */

static void cat_first_line(FILE *f, const char *label, const char *path)
{
    FILE *p = fopen(path, "r");
    char line[512];
    if (p && fgets(line, sizeof line, p)) {
        line[strcspn(line, "\n")] = 0;
        fprintf(f, "  %-22s %s\n", label, line);
    } else {
        fprintf(f, "  %-22s (unavailable)\n", label);
    }
    if (p) fclose(p);
}

void bench_print_environment(FILE *f)
{
    fprintf(f, "Measurement environment\n");

    FILE *p = fopen("/proc/cpuinfo", "r");
    char line[512];
    if (p) {
        while (fgets(line, sizeof line, f ? p : p)) {
            if (strncmp(line, "model name", 10) == 0) {
                char *c = strchr(line, ':');
                if (c) { c[strcspn(c, "\n")] = 0; fprintf(f, "  %-22s %s\n", "CPU", c + 2); }
                break;
            }
        }
        fclose(p);
    }

    cat_first_line(f, "governor",
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
    cat_first_line(f, "cur freq (kHz)",
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq");
    cat_first_line(f, "turbo disabled",
        "/sys/devices/system/cpu/intel_pstate/no_turbo");
    cat_first_line(f, "SMT",
        "/sys/devices/system/cpu/smt/control");
    cat_first_line(f, "ASLR",
        "/proc/sys/kernel/randomize_va_space");

    fprintf(f, "  %-22s %d\n", "pinned to cpu", sched_getcpu());
    fprintf(f, "  %-22s %.1f ns\n", "timer overhead", g_timer_ns);
    fprintf(f, "  %-22s %s\n", "cycle source",
            bench_cycles_available()
              ? "perf_event_open (retired core cycles)"
              : "UNAVAILABLE - cycle columns suppressed");
    if (g_tsc_ghz > 0)
        fprintf(f, "  %-22s %.4f GHz (informational; NOT used for cycles)\n",
                "TSC rate", g_tsc_ghz);
    fprintf(f, "\n");
}
