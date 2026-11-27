#include "../include/detection_examples.h"

#include <algorithm>
#include <cmath>
#include <intrin.h>
#include <limits>

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

struct TimingDistribution
{
    double Min;
    double Max;
    double Mean;
    double StdDev;
};

struct QpcReadStats
{
    DWORD Backwards;
    DWORD LargeGaps;
    double MaxGapMs;
};

struct SleepTimingStats
{
    TimingDistribution QpcMs;
    TimingDistribution TscCyclesPerMs;
    double MaxTickDriftMs;
};

struct CycleLatencyStats
{
    unsigned long long Median;
    unsigned long long P95;
};

static double QpcTicksToMs(LONGLONG ticks, const LARGE_INTEGER& frequency)
{
    return ((double)ticks * 1000.0) / (double)frequency.QuadPart;
}

static TimingDistribution SummarizeDoubles(const std::vector<double>& values)
{
    TimingDistribution out = {};
    double sum = 0.0;
    double variance = 0.0;

    if (values.empty())
    {
        return out;
    }

    out.Min = (std::numeric_limits<double>::max)();
    for (double value : values)
    {
        out.Min = std::min(out.Min, value);
        out.Max = std::max(out.Max, value);
        sum += value;
    }

    out.Mean = sum / (double)values.size();
    for (double value : values)
    {
        const double delta = value - out.Mean;
        variance += delta * delta;
    }
    out.StdDev = std::sqrt(variance / (double)values.size());
    return out;
}

static CycleLatencyStats SummarizeCycles(std::vector<unsigned long long> values)
{
    CycleLatencyStats out = {};

    if (values.empty())
    {
        return out;
    }

    std::sort(values.begin(), values.end());
    out.Median = values[values.size() / 2];
    out.P95 = values[(values.size() * 95) / 100];
    return out;
}

static DWORD_PTR LowestAffinityBit(DWORD_PTR mask)
{
    return mask & (~(mask - 1));
}

static DWORD_PTR PinCurrentThreadToSingleCpu()
{
    DWORD_PTR processMask = 0;
    DWORD_PTR systemMask = 0;
    DWORD_PTR selectedMask;
    DWORD_PTR previousMask;

    if (!GetProcessAffinityMask(GetCurrentProcess(), &processMask, &systemMask) || processMask == 0)
    {
        AES_LOG_WARN("GetProcessAffinityMask failed err=%lu processMask=0x%p", GetLastError(), (void*)processMask);
        return 0;
    }

    selectedMask = LowestAffinityBit(processMask);
    previousMask = SetThreadAffinityMask(GetCurrentThread(), selectedMask);
    if (previousMask == 0)
    {
        AES_LOG_WARN("SetThreadAffinityMask selectedMask=0x%p failed err=%lu", (void*)selectedMask, GetLastError());
        return 0;
    }

    Sleep(0);
    AES_LOG_DEBUG("Pinned timing scenario thread affinity selectedMask=0x%p previousMask=0x%p", (void*)selectedMask,
                  (void*)previousMask);
    return previousMask;
}

static void RestoreCurrentThreadAffinity(DWORD_PTR previousMask)
{
    if (previousMask != 0 && SetThreadAffinityMask(GetCurrentThread(), previousMask) == 0)
    {
        AES_LOG_WARN("Restoring thread affinity mask=0x%p failed err=%lu", (void*)previousMask, GetLastError());
    }
}

#if defined(_M_IX86) || defined(_M_X64)
static unsigned long long ReadTsc()
{
    return __rdtsc();
}

static unsigned long long ReadTscp()
{
    unsigned int aux = 0;
    return __rdtscp(&aux);
}

static unsigned long long MeasureCpuidCallCycles()
{
    int registers[4] = {};
    const unsigned long long start = ReadTscp();
    __cpuid(registers, 0);
    return ReadTscp() - start;
}

static unsigned long long MeasureQpcCallCycles()
{
    LARGE_INTEGER ignored;
    const unsigned long long start = ReadTscp();
    QueryPerformanceCounter(&ignored);
    return ReadTscp() - start;
}
#else
static unsigned long long ReadTsc()
{
    return 0;
}
#endif

static QpcReadStats MeasureQpcReadStability(const LARGE_INTEGER& frequency)
{
    static const DWORD kReadCount = 75000;
    static const double kLargeGapMs = 25.0;
    QpcReadStats stats = {};
    LARGE_INTEGER previous;

    QueryPerformanceCounter(&previous);
    for (DWORD i = 0; i < kReadCount; ++i)
    {
        LARGE_INTEGER current;
        LONGLONG delta;

        QueryPerformanceCounter(&current);
        delta = current.QuadPart - previous.QuadPart;
        if (delta < 0)
        {
            stats.Backwards += 1;
        }
        else
        {
            const double gapMs = QpcTicksToMs(delta, frequency);
            stats.MaxGapMs = std::max(stats.MaxGapMs, gapMs);
            if (gapMs >= kLargeGapMs)
            {
                stats.LargeGaps += 1;
            }
        }
        previous = current;
    }

    AES_LOG_DEBUG("QPC read stability reads=%lu backwards=%lu largeGaps=%lu maxGapMs=%.3f", kReadCount, stats.Backwards,
                  stats.LargeGaps, stats.MaxGapMs);
    return stats;
}

static bool MeasureSleepTiming(const LARGE_INTEGER& frequency, SleepTimingStats* stats)
{
    static const DWORD kSleepMs = 50;
    static const DWORD kSamples = 10;
    std::vector<double> qpcElapsedMs;
    std::vector<double> cyclesPerMs;
    double maxTickDriftMs = 0.0;

    if (stats == nullptr)
    {
        return false;
    }

    qpcElapsedMs.reserve(kSamples);
    cyclesPerMs.reserve(kSamples);

    for (DWORD i = 0; i < kSamples; ++i)
    {
        LARGE_INTEGER qpcStart;
        LARGE_INTEGER qpcEnd;
        ULONGLONG tickStart;
        ULONGLONG tickEnd;
        unsigned long long tscStart;
        unsigned long long tscEnd;
        double qpcMs;
        double tickMs;

        QueryPerformanceCounter(&qpcStart);
        tickStart = GetTickCount64();
        tscStart = ReadTsc();
        Sleep(kSleepMs);
        tscEnd = ReadTsc();
        tickEnd = GetTickCount64();
        QueryPerformanceCounter(&qpcEnd);

        qpcMs = QpcTicksToMs(qpcEnd.QuadPart - qpcStart.QuadPart, frequency);
        tickMs = (double)(tickEnd - tickStart);

        qpcElapsedMs.push_back(qpcMs);
        maxTickDriftMs = std::max(maxTickDriftMs, std::fabs(qpcMs - tickMs));
        if (qpcMs > 0.0 && tscEnd > tscStart)
        {
            cyclesPerMs.push_back((double)(tscEnd - tscStart) / qpcMs);
        }

        AES_LOG_DEBUG("Sleep timing sample=%lu requestedMs=%lu qpcMs=%.3f tickMs=%.3f cyclesPerMs=%.3f", i, kSleepMs,
                      qpcMs, tickMs, cyclesPerMs.empty() ? 0.0 : cyclesPerMs.back());
    }

    stats->QpcMs = SummarizeDoubles(qpcElapsedMs);
    stats->TscCyclesPerMs = SummarizeDoubles(cyclesPerMs);
    stats->MaxTickDriftMs = maxTickDriftMs;
    return !qpcElapsedMs.empty();
}

#if defined(_M_IX86) || defined(_M_X64)
static CycleLatencyStats MeasureCpuidLatency()
{
    static const DWORD kSamples = 256;
    std::vector<unsigned long long> samples;

    samples.reserve(kSamples);
    for (DWORD i = 0; i < 16; ++i)
    {
        (void)MeasureCpuidCallCycles();
    }
    for (DWORD i = 0; i < kSamples; ++i)
    {
        samples.push_back(MeasureCpuidCallCycles());
    }

    return SummarizeCycles(samples);
}

static CycleLatencyStats MeasureQpcLatency()
{
    static const DWORD kSamples = 256;
    std::vector<unsigned long long> samples;

    samples.reserve(kSamples);
    for (DWORD i = 0; i < 16; ++i)
    {
        (void)MeasureQpcCallCycles();
    }
    for (DWORD i = 0; i < kSamples; ++i)
    {
        samples.push_back(MeasureQpcCallCycles());
    }

    return SummarizeCycles(samples);
}
#endif

int ExampleRunCpuTimingQpc(int argc, wchar_t** argv)
{
    LARGE_INTEGER frequency;
    QpcReadStats qpcReadStats;
    SleepTimingStats sleepStats = {};
    DWORD_PTR previousAffinity = 0;
    DWORD score = 0;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0)
    {
        AES_LOG_ERROR("QueryPerformanceFrequency failed err=%lu frequency=%lld", GetLastError(), frequency.QuadPart);
        ExamplePrint("[FAIL] cpu-timing-qpc QueryPerformanceFrequency failed err=%lu\n", GetLastError());
        return 1;
    }

    previousAffinity = PinCurrentThreadToSingleCpu();
    AES_LOG_INFO("CPU timing/QPC scenario frequency=%lld", frequency.QuadPart);

    qpcReadStats = MeasureQpcReadStability(frequency);
    if (!MeasureSleepTiming(frequency, &sleepStats))
    {
        RestoreCurrentThreadAffinity(previousAffinity);
        ExamplePrint("[FAIL] cpu-timing-qpc failed to collect sleep timing samples\n");
        return 1;
    }

    if (qpcReadStats.Backwards > 0)
    {
        score += 5;
    }
    if (qpcReadStats.LargeGaps > 0)
    {
        score += 1;
    }
    if (sleepStats.QpcMs.Min < 35.0)
    {
        score += 4;
    }
    if (sleepStats.QpcMs.Max > 500.0)
    {
        score += 2;
    }
    if (sleepStats.MaxTickDriftMs > 35.0)
    {
        score += 3;
    }

    if (sleepStats.TscCyclesPerMs.Mean > 0.0)
    {
        const double relativeStdDev = sleepStats.TscCyclesPerMs.StdDev / sleepStats.TscCyclesPerMs.Mean;
        if (relativeStdDev > 0.15)
        {
            score += 2;
        }
        if (sleepStats.TscCyclesPerMs.Mean < 100000.0 || sleepStats.TscCyclesPerMs.Mean > 10000000.0)
        {
            score += 1;
        }
    }

#if defined(_M_IX86) || defined(_M_X64)
    {
        const CycleLatencyStats cpuidLatency = MeasureCpuidLatency();
        const CycleLatencyStats qpcLatency = MeasureQpcLatency();

        AES_LOG_INFO(
            "CPU timing latency cpuidMedianCycles=%llu cpuidP95Cycles=%llu qpcMedianCycles=%llu qpcP95Cycles=%llu",
            cpuidLatency.Median, cpuidLatency.P95, qpcLatency.Median, qpcLatency.P95);

        if (cpuidLatency.Median > 3000)
        {
            score += 4;
        }
        else if (cpuidLatency.Median > 1500)
        {
            score += 2;
        }

        if (qpcLatency.Median > 3000 || qpcLatency.P95 > 10000)
        {
            score += 2;
        }

        ExamplePrint(
            "[OK] cpu-timing-qpc evidenceScore=%lu qpcBackwards=%lu largeGaps=%lu maxGapMs=%.3f "
            "sleepMs{min=%.3f mean=%.3f max=%.3f} tickDriftMaxMs=%.3f "
            "tscCyclesPerMs{mean=%.0f rsd=%.3f} cpuidMedianCycles=%llu qpcMedianCycles=%llu\n",
            score, qpcReadStats.Backwards, qpcReadStats.LargeGaps, qpcReadStats.MaxGapMs, sleepStats.QpcMs.Min,
            sleepStats.QpcMs.Mean, sleepStats.QpcMs.Max, sleepStats.MaxTickDriftMs, sleepStats.TscCyclesPerMs.Mean,
            sleepStats.TscCyclesPerMs.Mean > 0.0 ? sleepStats.TscCyclesPerMs.StdDev / sleepStats.TscCyclesPerMs.Mean
                                                 : 0.0,
            cpuidLatency.Median, qpcLatency.Median);
    }
#else
    ExamplePrint("[OK] cpu-timing-qpc evidenceScore=%lu qpcBackwards=%lu largeGaps=%lu maxGapMs=%.3f "
                 "sleepMs{min=%.3f mean=%.3f max=%.3f} tickDriftMaxMs=%.3f\n",
                 score, qpcReadStats.Backwards, qpcReadStats.LargeGaps, qpcReadStats.MaxGapMs, sleepStats.QpcMs.Min,
                 sleepStats.QpcMs.Mean, sleepStats.QpcMs.Max, sleepStats.MaxTickDriftMs);
#endif

    RestoreCurrentThreadAffinity(previousAffinity);
    AES_LOG_INFO("CPU timing/QPC evidenceScore=%lu qpcBackwards=%lu qpcLargeGaps=%lu sleepMeanMs=%.3f", score,
                 qpcReadStats.Backwards, qpcReadStats.LargeGaps, sleepStats.QpcMs.Mean);
    return 0;
}
