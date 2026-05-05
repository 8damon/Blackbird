using System;

namespace BlackbirdInterface
{
    internal static class BrokerEtwEventMapper
    {
        internal static BrokerEtwEventView FromNative(BlackbirdNative.BkIpcEtwEvent etw)
        {
            bool isBlackbirdOwn = (etw.DetectionTraits & BlackbirdNative.IpcEtwTraitBlackbirdOwn) != 0;
            string source = isBlackbirdOwn
                                ? "BK/SR71"
                                : etw.Source switch { BlackbirdNative.IpcEtwSourceBlackbird => "BK",
                                                      BlackbirdNative.IpcEtwSourceThreatIntel => "ThreatIntel",
                                                      BlackbirdNative.IpcEtwSourceKernelNetwork => "KernelNetwork",
                                                      BlackbirdNative.IpcEtwSourceUserHook => "UserHook",
                                                      _ => "Unknown" };

            string eventName = BlackbirdNative.WideBufferToString(etw.EventName);
            if (string.IsNullOrWhiteSpace(eventName))
            {
                eventName = "unknown";
            }

            DateTime now = DateTime.UtcNow;
            var view = new BrokerEtwEventView { TimestampUtc = now,
                                                LastSeenUtc = now,
                                                Source = source,
                                                SourceId = etw.Source,
                                                Family = etw.Family,
                                                EventName = eventName,
                                                Task = etw.Task,
                                                Opcode = etw.Opcode,
                                                EventId = etw.EventId,
                                                EventProcessId = etw.EventProcessId,
                                                EventThreadId = etw.EventThreadId,
                                                Severity = etw.Severity,
                                                Flags = etw.Flags,
                                                DetectionTraits = etw.DetectionTraits,
                                                ActorPid = ResolveActorPid(etw),
                                                TargetPid = ResolveTargetPid(etw),
                                                ProcessPid = NarrowPid(etw.ProcessId) ?? 0,
                                                ThreadId = NarrowPid(etw.ThreadId) ?? 0,
                                                CallerPid = NarrowPid(etw.CallerPid) ?? 0,
                                                ExplicitTargetPid = NarrowPid(etw.TargetPid) ?? 0,
                                                ParentPid = NarrowPid(etw.ParentProcessId) ?? 0,
                                                CreatorPid = NarrowPid(etw.CreatorProcessId) ?? 0,
                                                CreatorThreadId = NarrowPid(etw.CreatorThreadId) ?? 0,
                                                CorrelationFlags = etw.CorrelationFlags,
                                                CorrelationAccessMask = etw.CorrelationAccessMask,
                                                CorrelationAgeMs = etw.CorrelationAgeMs,
                                                DetectionName = BlackbirdNative.AnsiBufferToString(etw.DetectionName),
                                                Reason = BlackbirdNative.WideBufferToString(etw.Reason),
                                                ClassName = BlackbirdNative.AnsiBufferToString(etw.ClassName),
                                                Operation = BlackbirdNative.AnsiBufferToString(etw.Operation),
                                                DesiredAccess = etw.DesiredAccess,
                                                OriginAddress = etw.OriginAddress,
                                                OriginProtect = etw.OriginProtect,
                                                StatusOpenProcess = etw.StatusOpenProcess,
                                                StatusBasicInfo = etw.StatusBasicInfo,
                                                StatusSectionName = etw.StatusSectionName,
                                                StackCount = etw.StackCount,
                                                Stack = etw.Stack ?? Array.Empty<ulong>(),
                                                DeepAllocationBase = etw.DeepAllocationBase,
                                                DeepRegionSize = etw.DeepRegionSize,
                                                DeepRegionProtect = etw.DeepRegionProtect,
                                                DeepRegionState = etw.DeepRegionState,
                                                DeepRegionType = etw.DeepRegionType,
                                                DeepSampleSize = etw.DeepSampleSize,
                                                DeepSample = etw.DeepSample ?? Array.Empty<byte>(),
                                                OriginPath = BlackbirdNative.WideBufferToString(etw.OriginPath),
                                                StartAddress = etw.StartAddress,
                                                ImageBase = etw.ImageBase,
                                                ImageSize = etw.ImageSize,
                                                StartRegionProtect = etw.StartRegionProtect,
                                                StartRegionState = etw.StartRegionState,
                                                StartRegionType = etw.StartRegionType,
                                                StartRegionStatus = etw.StartRegionStatus,
                                                SessionId = etw.SessionId,
                                                CreateStatus = etw.CreateStatus,
                                                ProcessStartKey = etw.ProcessStartKey,
                                                SignatureLevel = etw.SignatureLevel,
                                                SignatureType = etw.SignatureType,
                                                NotifyClass = etw.NotifyClass,
                                                DataType = etw.DataType,
                                                DataSize = etw.DataSize,
                                                HookArgCount = etw.HookArgCount,
                                                HookArgs = etw.HookArgs ?? Array.Empty<ulong>(),
                                                ImagePath = BlackbirdNative.WideBufferToString(etw.ImagePath),
                                                CommandLine = BlackbirdNative.WideBufferToString(etw.CommandLine),
                                                KeyPath = BlackbirdNative.WideBufferToString(etw.KeyPath),
                                                ValueName = BlackbirdNative.WideBufferToString(etw.ValueName),
                                                RepeatCount = 1 };

            ProcessIdentityResolver.Prime(view.ActorPid);
            ProcessIdentityResolver.Prime(view.TargetPid);
            return view;
        }

        private static uint ResolveActorPid(BlackbirdNative.BkIpcEtwEvent etw)
        {
            return etw.Family switch {
                BlackbirdNative.IpcEtwFamilyHandle or BlackbirdNative.IpcEtwFamilyApc =>
                    NarrowPid(etw.CallerPid) ?? NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                BlackbirdNative.IpcEtwFamilyThread =>
                    NarrowPid(etw.CreatorProcessId) ?? NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                BlackbirdNative.IpcEtwFamilyProcess => NarrowPid(etw.CreatorProcessId) ??
                                                       NarrowPid(etw.ParentProcessId) ?? NarrowPid(etw.ProcessId) ??
                                                       etw.EventProcessId,
                BlackbirdNative.IpcEtwFamilyImage or BlackbirdNative.IpcEtwFamilyRegistry or
                    BlackbirdNative.IpcEtwFamilyDetection or BlackbirdNative.IpcEtwFamilyThreatIntel or
                        BlackbirdNative.IpcEtwFamilyUserHook or BlackbirdNative.IpcEtwFamilySocket =>
                    NarrowPid(etw.ProcessId) ?? etw.EventProcessId,
                _ => NarrowPid(etw.ProcessId) ?? NarrowPid(etw.CallerPid) ?? etw.EventProcessId
            };
        }

        private static uint ResolveTargetPid(BlackbirdNative.BkIpcEtwEvent etw)
        {
            return etw.Family switch {
                BlackbirdNative.IpcEtwFamilyHandle or BlackbirdNative.IpcEtwFamilyApc or BlackbirdNative
                    .IpcEtwFamilyDetection or BlackbirdNative.IpcEtwFamilyThreatIntel => NarrowPid(etw.TargetPid) ?? 0,
                BlackbirdNative.IpcEtwFamilyThread or BlackbirdNative.IpcEtwFamilyProcess =>
                    NarrowPid(etw.ProcessId) ?? 0,
                BlackbirdNative.IpcEtwFamilyUserHook => NarrowPid(etw.TargetPid) ?? NarrowPid(etw.ProcessId) ?? 0,
                BlackbirdNative.IpcEtwFamilySocket => NarrowPid(etw.TargetPid) ?? NarrowPid(etw.ProcessId) ?? 0,
                _ => NarrowPid(etw.TargetPid) ?? 0
            };
        }

        private static uint? NarrowPid(ulong value) => value is > 0 and <= uint.MaxValue?(uint)value : null;
    }
}
