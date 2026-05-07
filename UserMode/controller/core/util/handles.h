#pragma once

#include <windows.h>
#include <memory>
#include <utility>

struct HandleDeleter
{
    using pointer = HANDLE;
    void operator()(HANDLE h) const noexcept
    {
        if (h && h != INVALID_HANDLE_VALUE)
        {
            CloseHandle(h);
        }
    }
};
using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

inline UniqueHandle MakeUniqueHandle(HANDLE h) noexcept
{
    return UniqueHandle(h);
}

template <typename T> struct LocalDeleter
{
    void operator()(T *p) const noexcept
    {
        if (p)
        {
            LocalFree(static_cast<HLOCAL>(p));
        }
    }
};
template <typename T> using UniqueLocalPtr = std::unique_ptr<T, LocalDeleter<T>>;

struct OwnedCriticalSection
{
    OwnedCriticalSection() noexcept
    {
        InitializeCriticalSection(&m_cs);
    }
    ~OwnedCriticalSection() noexcept
    {
        DeleteCriticalSection(&m_cs);
    }

    OwnedCriticalSection(const OwnedCriticalSection &) = delete;
    OwnedCriticalSection &operator=(const OwnedCriticalSection &) = delete;
    OwnedCriticalSection(OwnedCriticalSection &&) = delete;
    OwnedCriticalSection &operator=(OwnedCriticalSection &&) = delete;

    CRITICAL_SECTION *get() noexcept
    {
        return &m_cs;
    }
    const CRITICAL_SECTION *get() const noexcept
    {
        return &m_cs;
    }

  private:
    CRITICAL_SECTION m_cs;
};

struct ScopedCriticalSection
{
    explicit ScopedCriticalSection(CRITICAL_SECTION *cs) noexcept : m_cs(cs)
    {
        EnterCriticalSection(m_cs);
    }
    explicit ScopedCriticalSection(OwnedCriticalSection &cs) noexcept : m_cs(cs.get())
    {
        EnterCriticalSection(m_cs);
    }
    ~ScopedCriticalSection() noexcept
    {
        LeaveCriticalSection(m_cs);
    }

    ScopedCriticalSection(const ScopedCriticalSection &) = delete;
    ScopedCriticalSection &operator=(const ScopedCriticalSection &) = delete;

  private:
    CRITICAL_SECTION *m_cs;
};

struct ScopedSRWExclusive
{
    explicit ScopedSRWExclusive(SRWLOCK *lock) noexcept : m_lock(lock)
    {
        AcquireSRWLockExclusive(m_lock);
    }
    ~ScopedSRWExclusive() noexcept
    {
        ReleaseSRWLockExclusive(m_lock);
    }

    ScopedSRWExclusive(const ScopedSRWExclusive &) = delete;
    ScopedSRWExclusive &operator=(const ScopedSRWExclusive &) = delete;

  private:
    SRWLOCK *m_lock;
};

struct ScopedSRWShared
{
    explicit ScopedSRWShared(SRWLOCK *lock) noexcept : m_lock(lock)
    {
        AcquireSRWLockShared(m_lock);
    }
    ~ScopedSRWShared() noexcept
    {
        ReleaseSRWLockShared(m_lock);
    }

    ScopedSRWShared(const ScopedSRWShared &) = delete;
    ScopedSRWShared &operator=(const ScopedSRWShared &) = delete;

  private:
    SRWLOCK *m_lock;
};
