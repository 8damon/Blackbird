#define NOMINMAX

#include "pipe.h"

namespace XIPC
{
    bool SendHello()
    {
        return Initialize();
    }

    bool RequestNumberForName(const std::wstring& name, DWORD& outValue)
    {
        (void)name;
        outValue = 0;
        return false;
    }

    bool RequestNameForNumber(DWORD ssn, std::wstring& outName)
    {
        (void)ssn;
        outName.clear();
        return false;
    }
}

