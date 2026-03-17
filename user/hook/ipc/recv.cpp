#include "pipe.h"

namespace XIPC
{
    bool RecvHello(HelloMessage& out)
    {
        if (!Initialize())
            return false;

        out.magic = KHOK_MAGIC;
        out.version = KHOK_VERSION;
        out.pid = GetCurrentProcessId();
        out.reserved = 0;

        return true;
    }
}

