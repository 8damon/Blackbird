#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib")

static int contains_vm_string(const char *s)
{
    const char *k[] = {"vmware",          "virtualbox",       "vbox",     "kvm", "qemu", "xen", "hyper-v",
                       "virtual machine", "virtual platform", "parallels"};

    for (int i = 0; i < sizeof(k) / sizeof(k[0]); i++)
    {
        if (_stricmp(s, k[i]) == 0 || strstr(_strlwr(_strdup(s)), k[i]))
            return 1;
    }

    return 0;
}

static int check_vm_mac(const BYTE *mac)
{
    const BYTE vm_prefix[][3] = {{0x00, 0x05, 0x69}, {0x00, 0x0C, 0x29}, {0x00, 0x1C, 0x14}, {0x00, 0x50, 0x56},
                                 {0x08, 0x00, 0x27}, {0x52, 0x54, 0x00}, {0x00, 0x15, 0x5D}, {0x00, 0x16, 0x3E}};

    for (int i = 0; i < sizeof(vm_prefix) / sizeof(vm_prefix[0]); i++)
    {
        if (!memcmp(mac, vm_prefix[i], 3))
            return 1;
    }

    return 0;
}

static int mac_vm_check()
{
    ULONG size = sizeof(IP_ADAPTER_INFO);

    IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)malloc(size);

    if (GetAdaptersInfo(info, &size) == ERROR_BUFFER_OVERFLOW)
    {
        free(info);
        info = (IP_ADAPTER_INFO *)malloc(size);
    }

    if (GetAdaptersInfo(info, &size) != NO_ERROR)
        return 0;

    int score = 0;

    IP_ADAPTER_INFO *a = info;

    while (a)
    {
        if (check_vm_mac(a->Address))
            score += 3;

        if (contains_vm_string(a->Description))
            score += 2;

        a = a->Next;
    }

    free(info);

    return score;
}

static int bios_vm_check()
{
    char buf[256];

    DWORD sz = sizeof(buf);

    if (RegGetValueA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer", RRF_RT_REG_SZ,
                     NULL, buf, &sz) == ERROR_SUCCESS)
    {
        printf("Manufacturer: %s\n", buf);

        if (contains_vm_string(buf))
            return 3;
    }

    return 0;
}

int main()
{
    int score = 0;

    printf("Running VM heuristic checks\n\n");

    score += mac_vm_check();
    score += bios_vm_check();

    printf("\nVM evidence score: %d\n", score);

    if (score >= 3)
        printf("Likely running inside a VM\n");
    else
        printf("No strong VM indicators\n");

    return 0;
}