using System;
using System.Collections.Generic;
using System.Text;

namespace BlackbirdInterface
{
    internal static class EventDetailFormatting
    {
        private const uint ProcessCreateThread = 0x0002;
        private const uint ProcessVmOperation = 0x0008;
        private const uint ProcessVmRead = 0x0010;
        private const uint ProcessVmWrite = 0x0020;
        private const uint ProcessDupHandle = 0x0040;
        private const uint ProcessQueryInformation = 0x0400;
        private const uint ProcessQueryLimitedInformation = 0x1000;
        private const uint ProcessSuspendResume = 0x0800;
        private const uint Synchronize = 0x00100000;
        private const uint ProcessAllAccess = 0x001F0FFF;

        private const uint ThreadSuspendResume = 0x0002;
        private const uint ThreadQueryInformation = 0x0040;
        private const uint ThreadQueryLimitedInformation = 0x0800;
        private const uint ThreadGetContext = 0x0008;
        private const uint ThreadSetContext = 0x0010;
        private const uint ThreadAllAccess = 0x001F03FF;

        private const uint HandleFlagStackSpoofSuspect = 0x00000800;
        private const uint HandleFlagSyscallExportMismatch = 0x00002000;
        private const uint HandleFlagModuleChainSane = 0x00004000;
        private const uint HandleFlagUnwindMetadataValid = 0x00008000;
        private const uint HandleFlagFramesOutsideTebStack = 0x00020000;
        private const uint HandleFlagThreadObject = 0x00000010;
        private const uint HandleFlagDuplicateOperation = 0x00000020;
        private const uint HandleFlagExecProtect = 0x00000001;
        private const uint HandleFlagFromNtdll = 0x00000002;
        private const uint HandleFlagFromExe = 0x00000004;

        private const uint ThreadFlagRemoteCreator = 0x00000004;
        private const uint ThreadFlagOutsideMainImage = 0x00000008;
        private const uint ThreadFlagCorrelatedIntent = 0x00000010;
        private const uint ThreadFlagCorrMemory = 0x00000020;
        private const uint ThreadFlagCorrThreadContext = 0x00000040;
        private const uint ThreadFlagCorrDupHandle = 0x00000080;

        private const uint IntentProcessMemory = 0x00000001;
        private const uint IntentThreadContext = 0x00000002;
        private const uint IntentDupHandle = 0x00000004;

        internal static string SeverityLabel(uint severity)
        {
            if (severity >= 8)
            {
                return "Critical";
            }
            if (severity >= 6)
            {
                return "High";
            }
            if (severity >= 4)
            {
                return "Medium";
            }
            if (severity >= 2)
            {
                return "Low";
            }
            return "Info";
        }

        internal static string SeverityLabelFromText(string? severity)
        {
            if (string.IsNullOrWhiteSpace(severity))
            {
                return "Info";
            }

            string value = severity.Trim();
            if (uint.TryParse(value, out uint numeric))
            {
                return SeverityLabel(numeric);
            }

            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                uint.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out uint hexNumeric))
            {
                return SeverityLabel(hexNumeric);
            }

            if (value.Contains("critical", StringComparison.OrdinalIgnoreCase))
            {
                return "Critical";
            }
            if (value.Contains("high", StringComparison.OrdinalIgnoreCase))
            {
                return "High";
            }
            if (value.Contains("medium", StringComparison.OrdinalIgnoreCase))
            {
                return "Medium";
            }
            if (value.Contains("low", StringComparison.OrdinalIgnoreCase))
            {
                return "Low";
            }
            if (value.Contains("info", StringComparison.OrdinalIgnoreCase))
            {
                return "Info";
            }

            return value;
        }

        internal static string RelationSeverity(ProcessRelationView view)
        {
            if (string.Equals(view.RelationType, "HandleOpen", StringComparison.OrdinalIgnoreCase))
            {
                bool anomaly = (view.LastFlags & (HandleFlagStackSpoofSuspect | HandleFlagSyscallExportMismatch)) != 0;
                bool suspiciousContext = (view.LastFlags & (HandleFlagModuleChainSane | HandleFlagUnwindMetadataValid)) == 0;
                bool highAccess = (view.LastAccessMask & (ProcessVmWrite | ProcessCreateThread | ThreadSetContext |
                                                          ThreadSuspendResume | ProcessAllAccess | ThreadAllAccess)) != 0;
                bool mediumAccess = (view.LastAccessMask & (ProcessVmOperation | ProcessDupHandle | ThreadGetContext |
                                                            ProcessSuspendResume | ProcessVmRead)) != 0;
                if (anomaly || suspiciousContext)
                {
                    return "High";
                }
                if (highAccess)
                {
                    return "Medium";
                }
                if (mediumAccess)
                {
                    return "Low";
                }
                return "Info";
            }

            bool criticalThread = (view.LastFlags & (ThreadFlagRemoteCreator | ThreadFlagOutsideMainImage |
                                                     ThreadFlagCorrMemory | ThreadFlagCorrThreadContext)) != 0;
            bool mediumThread = (view.LastFlags & (ThreadFlagCorrelatedIntent | ThreadFlagCorrDupHandle)) != 0;
            if (criticalThread)
            {
                return "High";
            }
            if (mediumThread)
            {
                return "Medium";
            }
            return "Low";
        }

        internal static string DescribeHandleAccess(uint access)
        {
            var tokens = new List<string>();
            if ((access & ProcessAllAccess) == ProcessAllAccess)
            {
                tokens.Add("PROCESS_ALL_ACCESS");
            }
            if ((access & ProcessCreateThread) != 0)
            {
                tokens.Add("PROCESS_CREATE_THREAD");
            }
            if ((access & ProcessVmOperation) != 0)
            {
                tokens.Add("PROCESS_VM_OPERATION");
            }
            if ((access & ProcessVmWrite) != 0)
            {
                tokens.Add("PROCESS_VM_WRITE");
            }
            if ((access & ProcessVmRead) != 0)
            {
                tokens.Add("PROCESS_VM_READ");
            }
            if ((access & ProcessDupHandle) != 0)
            {
                tokens.Add("PROCESS_DUP_HANDLE");
            }
            if ((access & ProcessQueryInformation) != 0)
            {
                tokens.Add("PROCESS_QUERY_INFORMATION");
            }
            if ((access & ProcessQueryLimitedInformation) != 0)
            {
                tokens.Add("PROCESS_QUERY_LIMITED_INFORMATION");
            }
            if ((access & ProcessSuspendResume) != 0)
            {
                tokens.Add("PROCESS_SUSPEND_RESUME");
            }
            if ((access & Synchronize) != 0)
            {
                tokens.Add("SYNCHRONIZE");
            }
            if ((access & ThreadSetContext) != 0)
            {
                tokens.Add("THREAD_SET_CONTEXT");
            }
            if ((access & ThreadGetContext) != 0)
            {
                tokens.Add("THREAD_GET_CONTEXT");
            }
            if ((access & ThreadQueryInformation) != 0)
            {
                tokens.Add("THREAD_QUERY_INFORMATION");
            }
            if ((access & ThreadQueryLimitedInformation) != 0)
            {
                tokens.Add("THREAD_QUERY_LIMITED_INFORMATION");
            }
            if ((access & ThreadSuspendResume) != 0)
            {
                tokens.Add("THREAD_SUSPEND_RESUME");
            }
            if ((access & ThreadAllAccess) == ThreadAllAccess)
            {
                tokens.Add("THREAD_ALL_ACCESS");
            }

            if (tokens.Count == 0)
            {
                tokens.Add("NONE");
            }

            return string.Join(" | ", tokens);
        }

        internal static string ResolveDirectSyscallApi(uint desiredAccess, uint handleFlags, string? detection = null)
        {
            string det = detection ?? string.Empty;
            if ((handleFlags & HandleFlagDuplicateOperation) != 0 ||
                det.Contains("DUPLICATE_OPERATION", StringComparison.OrdinalIgnoreCase) ||
                det.Contains("DUP_HANDLE", StringComparison.OrdinalIgnoreCase))
            {
                return "NtDuplicateObject";
            }

            if ((handleFlags & HandleFlagThreadObject) != 0 ||
                (desiredAccess & ThreadAllAccess) == ThreadAllAccess ||
                (desiredAccess & (ThreadSetContext | ThreadGetContext | ThreadSuspendResume | ThreadQueryInformation | ThreadQueryLimitedInformation)) != 0)
            {
                return "NtOpenThread";
            }

            return "NtOpenProcess";
        }

        internal static bool TryExtractSyscallId(byte[]? sample, int sampleSize, out uint syscallId)
        {
            syscallId = 0;
            if (sample == null || sampleSize <= 0)
            {
                return false;
            }

            int count = Math.Min(sample.Length, sampleSize);
            if (count < 11)
            {
                return false;
            }

            for (int i = 0; i <= count - 11; i += 1)
            {
                if (sample[i] == 0x4C &&
                    sample[i + 1] == 0x8B &&
                    sample[i + 2] == 0xD1 &&
                    sample[i + 3] == 0xB8 &&
                    sample[i + 8] == 0x0F &&
                    sample[i + 9] == 0x05)
                {
                    syscallId = (uint)(sample[i + 4] |
                                       (sample[i + 5] << 8) |
                                       (sample[i + 6] << 16) |
                                       (sample[i + 7] << 24));
                    return true;
                }
            }

            return false;
        }

        internal static string BuildDirectSyscallLabel(uint desiredAccess, uint handleFlags, byte[]? sample, int sampleSize, string? detection = null)
        {
            string api = ResolveDirectSyscallApi(desiredAccess, handleFlags, detection);
            return TryExtractSyscallId(sample, sampleSize, out uint syscallId)
                ? $"{api} (id=0x{syscallId:X})"
                : api;
        }

        internal static string BuildDirectSyscallSummary(
            string actor,
            string target,
            uint desiredAccess,
            uint handleFlags,
            byte[]? sample,
            int sampleSize,
            string? originPath = null,
            string? detection = null)
        {
            string syscallLabel = BuildDirectSyscallLabel(desiredAccess, handleFlags, sample, sampleSize, detection);
            string accessSummary = SummarizePrimaryHandleAccess(desiredAccess);
            string objectKind = (handleFlags & HandleFlagThreadObject) != 0 ? "thread" : "process";
            string originModule = ModuleNameFromPath(originPath);
            string signalSummary = SummarizeDirectSyscallSignals(handleFlags);

            var sb = new StringBuilder(192);
            sb.Append(string.IsNullOrWhiteSpace(actor) ? "Actor" : actor.Trim())
              .Append(" issued ")
              .Append(syscallLabel)
              .Append(" against ")
              .Append(string.IsNullOrWhiteSpace(target) ? "target" : target.Trim())
              .Append(" for ")
              .Append(accessSummary)
              .Append(" on a ")
              .Append(objectKind)
              .Append(" handle");

            if (!string.Equals(originModule, "unknown", StringComparison.OrdinalIgnoreCase))
            {
                sb.Append(" via ").Append(originModule);
            }

            if (!string.IsNullOrWhiteSpace(signalSummary))
            {
                sb.Append("; ").Append(signalSummary);
            }

            sb.Append('.');
            return sb.ToString();
        }

        internal static string DescribeHandleFlags(uint flags)
        {
            return DescribeByBits(flags, new (uint Bit, string Name)[]
            {
                (0x00000001, "EXEC_PROTECT"),
                (0x00000002, "FROM_NTDLL"),
                (0x00000004, "FROM_EXE"),
                (0x00000008, "MEMORY_RELATED"),
                (0x00000010, "THREAD_OBJECT"),
                (0x00000020, "DUPLICATE_OPERATION"),
                (0x00000040, "DEEP_PATH_CANDIDATE"),
                (0x00000080, "DEEP_PATH_CAPTURED"),
                (0x00000100, "DEEP_PATH_CACHE_HIT"),
                (0x00000200, "RETURN_ADDRESS_VALID"),
                (0x00000400, "STACK_VALIDATED"),
                (0x00000800, "STACK_SPOOF_SUSPECT"),
                (0x00001000, "SYSCALL_EXPORT_MATCH"),
                (0x00002000, "SYSCALL_EXPORT_MISMATCH"),
                (0x00004000, "MODULE_CHAIN_SANE"),
                (0x00008000, "UNWIND_METADATA_VALID"),
                (0x00010000, "TEB_STACK_BOUNDS_VALID"),
                (0x00020000, "FRAMES_OUTSIDE_TEB_STACK")
            });
        }

        private static string SummarizePrimaryHandleAccess(uint access)
        {
            if ((access & ProcessAllAccess) == ProcessAllAccess)
            {
                return "PROCESS_ALL_ACCESS";
            }

            if ((access & ThreadAllAccess) == ThreadAllAccess)
            {
                return "THREAD_ALL_ACCESS";
            }

            if ((access & ProcessCreateThread) != 0)
            {
                return "PROCESS_CREATE_THREAD";
            }

            if ((access & ThreadSetContext) != 0)
            {
                return "THREAD_SET_CONTEXT";
            }

            if ((access & ThreadGetContext) != 0)
            {
                return "THREAD_GET_CONTEXT";
            }

            if ((access & ProcessVmWrite) != 0)
            {
                return "PROCESS_VM_WRITE";
            }

            if ((access & ProcessVmOperation) != 0)
            {
                return "PROCESS_VM_OPERATION";
            }

            if ((access & ProcessDupHandle) != 0)
            {
                return "PROCESS_DUP_HANDLE";
            }

            if ((access & ProcessVmRead) != 0)
            {
                return "PROCESS_VM_READ";
            }

            if ((access & ThreadSuspendResume) != 0 || (access & ProcessSuspendResume) != 0)
            {
                return "SUSPEND_RESUME";
            }

            return access == 0 ? "unspecified access" : $"0x{access:X8}";
        }

        private static string SummarizeDirectSyscallSignals(uint handleFlags)
        {
            var signals = new List<string>();
            if ((handleFlags & HandleFlagSyscallExportMismatch) != 0)
            {
                signals.Add("the observed syscall id did not match the expected ntdll export");
            }

            if ((handleFlags & HandleFlagStackSpoofSuspect) != 0)
            {
                signals.Add("captured frames looked stack-spoofed");
            }

            if ((handleFlags & HandleFlagExecProtect) != 0 && (handleFlags & HandleFlagFromNtdll) == 0)
            {
                if ((handleFlags & HandleFlagFromExe) != 0)
                {
                    signals.Add("execution originated from executable image code outside ntdll");
                }
                else
                {
                    signals.Add("execution originated from executable memory outside the known syscall stubs");
                }
            }

            return signals.Count == 0 ? string.Empty : string.Join("; ", signals);
        }

        internal static string DescribeThreadFlags(uint flags)
        {
            return DescribeByBits(flags, new (uint Bit, string Name)[]
            {
                (0x00000001, "GOT_START"),
                (0x00000002, "GOT_RANGE"),
                (0x00000004, "REMOTE_CREATOR"),
                (0x00000008, "OUTSIDE_MAIN_IMG"),
                (0x00000010, "CORRELATED_INTENT"),
                (0x00000020, "CORR_MEMORY"),
                (0x00000040, "CORR_THREAD_CTX"),
                (0x00000080, "CORR_DUP_HANDLE"),
                (0x00000100, "START_REGION_EXEC")
            });
        }

        internal static string DescribeCorrelationFlags(uint flags)
        {
            return DescribeByBits(flags, new (uint Bit, string Name)[]
            {
                (IntentProcessMemory, "INTENT_PROCESS_MEMORY"),
                (IntentThreadContext, "INTENT_THREAD_CONTEXT"),
                (IntentDupHandle, "INTENT_DUP_HANDLE")
            });
        }

        internal static string DescribeMemoryProtection(uint protect)
        {
            uint baseProtect = protect & 0xFFu;
            var labels = new List<string>();
            labels.Add(baseProtect switch
            {
                0x01 => "PAGE_NOACCESS",
                0x02 => "PAGE_READONLY",
                0x04 => "PAGE_READWRITE",
                0x08 => "PAGE_WRITECOPY",
                0x10 => "PAGE_EXECUTE",
                0x20 => "PAGE_EXECUTE_READ",
                0x40 => "PAGE_EXECUTE_READWRITE",
                0x80 => "PAGE_EXECUTE_WRITECOPY",
                _ => "UNKNOWN"
            });

            if ((protect & 0x100u) != 0)
            {
                labels.Add("PAGE_GUARD");
            }
            if ((protect & 0x200u) != 0)
            {
                labels.Add("PAGE_NOCACHE");
            }
            if ((protect & 0x400u) != 0)
            {
                labels.Add("PAGE_WRITECOMBINE");
            }

            return string.Join(" | ", labels);
        }

        internal static string DescribeMemoryState(uint state)
        {
            return state switch
            {
                0x00001000 => "MEM_COMMIT",
                0x00002000 => "MEM_RESERVE",
                0x00010000 => "MEM_FREE",
                _ => "UNKNOWN"
            };
        }

        internal static string DescribeMemoryType(uint type)
        {
            var labels = new List<string>();
            if ((type & 0x00020000u) != 0)
            {
                labels.Add("MEM_PRIVATE");
            }
            if ((type & 0x00040000u) != 0)
            {
                labels.Add("MEM_MAPPED");
            }
            if ((type & 0x01000000u) != 0)
            {
                labels.Add("MEM_IMAGE");
            }

            return labels.Count == 0 ? "UNKNOWN" : string.Join(" | ", labels);
        }

        internal static string ModuleNameFromPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "unknown";
            }

            string cleaned = path.Trim().Replace('/', '\\');
            int slash = cleaned.LastIndexOf('\\');
            return slash >= 0 && slash + 1 < cleaned.Length ? cleaned[(slash + 1)..] : cleaned;
        }

        internal static string FormatSampleHex(byte[]? sample, int sampleSize)
        {
            if (sample == null || sampleSize <= 0)
            {
                return "<none>";
            }

            int count = Math.Min(sampleSize, sample.Length);
            if (count <= 0)
            {
                return "<none>";
            }

            var sb = new StringBuilder(count * 3);
            for (int i = 0; i < count; i += 1)
            {
                if (i > 0)
                {
                    sb.Append(' ');
                }
                sb.Append(sample[i].ToString("X2"));
            }

            return sb.ToString();
        }

        internal static string InferSampleDisassembly(byte[]? sample, int sampleSize)
        {
            if (sample == null || sampleSize <= 0)
            {
                return "unavailable";
            }

            int count = Math.Min(sampleSize, sample.Length);
            if (count < 6)
            {
                return "insufficient bytes";
            }

            for (int i = 0; i <= count - 11; i += 1)
            {
                if (sample[i] == 0x4C && sample[i + 1] == 0x8B && sample[i + 2] == 0xD1 &&
                    sample[i + 3] == 0xB8 && sample[i + 8] == 0x0F && sample[i + 9] == 0x05)
                {
                    uint syscallId = (uint)(sample[i + 4] |
                                            (sample[i + 5] << 8) |
                                            (sample[i + 6] << 16) |
                                            (sample[i + 7] << 24));
                    return $"syscall stub pattern: mov r10,rcx; mov eax,0x{syscallId:X}; syscall";
                }
            }

            for (int i = 0; i <= count - 5; i += 1)
            {
                if (sample[i] == 0xE9)
                {
                    return "relative jump trampoline pattern";
                }
                if (sample[i] == 0xFF && sample[i + 1] == 0x25)
                {
                    return "absolute jump thunk pattern";
                }
            }

            return "no known syscall/trampoline signature";
        }

        internal static string FormatSampleDisassembly(
            byte[]? sample,
            int sampleSize,
            ulong originAddress = 0,
            string? modulePath = null,
            ulong regionBase = 0,
            ulong regionSize = 0,
            uint regionProtect = 0,
            uint regionState = 0,
            uint regionType = 0)
        {
            if (sample == null || sampleSize <= 0)
            {
                return "unavailable";
            }

            int count = Math.Min(sampleSize, sample.Length);
            if (count <= 0)
            {
                return "unavailable";
            }

            var sb = new StringBuilder(512);
            sb.Append("len=").Append(count).Append(" bytes");
            if (!string.IsNullOrWhiteSpace(modulePath))
            {
                sb.Append('\n')
                  .Append("module: ")
                  .Append(ModuleNameFromPath(modulePath))
                  .Append(" (")
                  .Append(modulePath)
                  .Append(')');
            }
            if (originAddress != 0)
            {
                ulong pageBase = originAddress & ~0xFFFUL;
                sb.Append('\n')
                  .Append("origin: 0x")
                  .Append(originAddress.ToString("X"))
                  .Append(" page: 0x")
                  .Append(pageBase.ToString("X"));
            }
            if (regionBase != 0 || regionSize != 0 || regionProtect != 0 || regionState != 0 || regionType != 0)
            {
                ulong regionEnd = regionSize == 0 ? regionBase : (regionBase + regionSize);
                sb.Append('\n')
                  .Append("region: 0x")
                  .Append(regionBase.ToString("X"))
                  .Append("-0x")
                  .Append(regionEnd.ToString("X"))
                  .Append(" size=0x")
                  .Append(regionSize.ToString("X"));
                sb.Append('\n')
                  .Append("vad: protect=0x")
                  .Append(regionProtect.ToString("X8"))
                  .Append(" (")
                  .Append(DescribeMemoryProtection(regionProtect))
                  .Append(") state=0x")
                  .Append(regionState.ToString("X8"))
                  .Append(" (")
                  .Append(DescribeMemoryState(regionState))
                  .Append(") type=0x")
                  .Append(regionType.ToString("X8"))
                  .Append(" (")
                  .Append(DescribeMemoryType(regionType))
                  .Append(')');
            }
            sb.Append('\n').Append("summary: ").Append(InferSampleDisassembly(sample, count));

            int offset = 0;
            int emitted = 0;
            const int MaxInstructions = 24;
            while (offset < count && emitted < MaxInstructions)
            {
                int length;
                string mnemonic;
                if (!TryDecodeX64Instruction(sample, count, offset, out length, out mnemonic))
                {
                    length = 1;
                    mnemonic = $"db 0x{sample[offset]:X2}";
                }

                string bytes = FormatSampleBytes(sample, offset, length);
                string address = originAddress != 0
                    ? $"0x{(originAddress + (ulong)offset):X}"
                    : $"+0x{offset:X2}";

                sb.Append('\n')
                  .Append(address)
                  .Append(": ")
                  .Append(bytes.PadRight(24))
                  .Append(' ')
                  .Append(mnemonic);

                offset += length;
                emitted += 1;
            }

            if (offset < count)
            {
                sb.Append('\n').Append("...");
            }

            return sb.ToString();
        }

        private static string FormatSampleBytes(byte[] sample, int offset, int length)
        {
            int count = Math.Min(length, sample.Length - offset);
            if (count <= 0)
            {
                return string.Empty;
            }

            var sb = new StringBuilder(count * 3);
            for (int i = 0; i < count; i += 1)
            {
                if (i > 0)
                {
                    sb.Append(' ');
                }
                sb.Append(sample[offset + i].ToString("X2"));
            }

            return sb.ToString();
        }

        private static string FormatRelativeTarget(int offset, int instructionLength, int displacement)
        {
            int target = offset + instructionLength + displacement;
            return target >= 0
                ? $"+0x{target:X}"
                : $"-0x{(-target):X}";
        }

        private static bool TryDecodeX64Instruction(
            byte[] sample,
            int count,
            int offset,
            out int length,
            out string mnemonic)
        {
            length = 0;
            mnemonic = string.Empty;

            if (offset < 0 || offset >= count)
            {
                return false;
            }

            int remaining = count - offset;
            byte b0 = sample[offset];

            if (remaining >= 11 &&
                b0 == 0x4C && sample[offset + 1] == 0x8B && sample[offset + 2] == 0xD1 &&
                sample[offset + 3] == 0xB8 && sample[offset + 8] == 0x0F && sample[offset + 9] == 0x05 &&
                sample[offset + 10] == 0xC3)
            {
                uint syscallId = (uint)(sample[offset + 4] |
                                        (sample[offset + 5] << 8) |
                                        (sample[offset + 6] << 16) |
                                        (sample[offset + 7] << 24));
                length = 11;
                mnemonic = $"mov r10, rcx; mov eax, 0x{syscallId:X}; syscall; ret";
                return true;
            }

            if (remaining >= 4 &&
                b0 == 0xF3 && sample[offset + 1] == 0x0F && sample[offset + 2] == 0x1E && sample[offset + 3] == 0xFA)
            {
                length = 4;
                mnemonic = "endbr64";
                return true;
            }

            if (remaining >= 3 && b0 == 0x4C && sample[offset + 1] == 0x8B && sample[offset + 2] == 0xD1)
            {
                length = 3;
                mnemonic = "mov r10, rcx";
                return true;
            }

            if (remaining >= 5 && b0 == 0xB8)
            {
                uint imm = (uint)(sample[offset + 1] |
                                  (sample[offset + 2] << 8) |
                                  (sample[offset + 3] << 16) |
                                  (sample[offset + 4] << 24));
                length = 5;
                mnemonic = $"mov eax, 0x{imm:X}";
                return true;
            }

            if (remaining >= 2 && b0 == 0x0F && sample[offset + 1] == 0x05)
            {
                length = 2;
                mnemonic = "syscall";
                return true;
            }

            if (remaining >= 7 && b0 == 0x48 && sample[offset + 1] == 0x8D && sample[offset + 2] == 0x05)
            {
                int rel = BitConverter.ToInt32(sample, offset + 3);
                length = 7;
                mnemonic = $"lea rax, [rip{(rel >= 0 ? "+" : "-")}0x{Math.Abs(rel):X}] ; -> {FormatRelativeTarget(offset, length, rel)}";
                return true;
            }

            if (remaining >= 6 && b0 == 0xFF && sample[offset + 1] == 0x25)
            {
                int rel = BitConverter.ToInt32(sample, offset + 2);
                length = 6;
                mnemonic = $"jmp qword ptr [rip{(rel >= 0 ? "+" : "-")}0x{Math.Abs(rel):X}] ; -> {FormatRelativeTarget(offset, length, rel)}";
                return true;
            }

            if (remaining >= 5 && b0 == 0xE9)
            {
                int rel = BitConverter.ToInt32(sample, offset + 1);
                length = 5;
                mnemonic = $"jmp {FormatRelativeTarget(offset, length, rel)}";
                return true;
            }

            if (remaining >= 2 && b0 == 0xEB)
            {
                int rel = (sbyte)sample[offset + 1];
                length = 2;
                mnemonic = $"jmp short {FormatRelativeTarget(offset, length, rel)}";
                return true;
            }

            if (remaining >= 4 && b0 == 0x48 && sample[offset + 1] == 0x83 && sample[offset + 2] == 0xEC)
            {
                length = 4;
                mnemonic = $"sub rsp, 0x{sample[offset + 3]:X2}";
                return true;
            }

            if (remaining >= 4 && b0 == 0x48 && sample[offset + 1] == 0x83 && sample[offset + 2] == 0xC4)
            {
                length = 4;
                mnemonic = $"add rsp, 0x{sample[offset + 3]:X2}";
                return true;
            }

            if (b0 == 0xC3)
            {
                length = 1;
                mnemonic = "ret";
                return true;
            }

            if (b0 == 0x90)
            {
                length = 1;
                mnemonic = "nop";
                return true;
            }

            if (b0 == 0xCC)
            {
                length = 1;
                mnemonic = "int3";
                return true;
            }

            return false;
        }

        private static string DescribeByBits(uint flags, IReadOnlyList<(uint Bit, string Name)> table)
        {
            var tokens = new List<string>();
            foreach (var entry in table)
            {
                if ((flags & entry.Bit) != 0)
                {
                    tokens.Add(entry.Name);
                }
            }

            if (tokens.Count == 0)
            {
                return "NONE";
            }

            return string.Join(" | ", tokens);
        }
    }
}
