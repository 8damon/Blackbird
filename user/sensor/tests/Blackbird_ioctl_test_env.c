#include "blackbird_ioctl_test_internal.h"
BOOL EnvFlagEnabled(_In_z_ const char *Name, _In_ BOOL DefaultValue)
{
    char value[16];
    size_t i;

    if (Name == NULL)
    {
        return DefaultValue;
    }

    if (GetEnvironmentVariableA(Name, value, (DWORD)RTL_NUMBER_OF(value)) == 0)
    {
        return DefaultValue;
    }

    for (i = 0; i < RTL_NUMBER_OF(value) && value[i] != '\0'; ++i)
    {
        if (value[i] >= 'A' && value[i] <= 'Z')
        {
            value[i] = (char)(value[i] - 'A' + 'a');
        }
    }

    if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "on") == 0)
    {
        return TRUE;
    }
    if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 || strcmp(value, "no") == 0 || strcmp(value, "off") == 0)
    {
        return FALSE;
    }

    return DefaultValue;
}
