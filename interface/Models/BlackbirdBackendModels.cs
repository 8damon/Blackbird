using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json.Serialization;

namespace BlackbirdInterface
{
    internal sealed class IoctlParsedEvent
    {
        public uint Type { get; set; }
        public uint Sequence { get; set; }
        public uint StreamMask { get; set; }

        public uint CallerPid { get; set; }
        public uint TargetPid { get; set; }
        public uint DesiredAccess { get; set; }
        public uint HandleClass { get; set; }
        public uint HandleFlags { get; set; }
        public ulong OriginAddress { get; set; }
        public uint OriginProtect { get; set; }
        public uint FrameCount { get; set; }
        public ulong[] Frames { get; set; } = Array.Empty<ulong>();
        public int StatusOpenProcess { get; set; }
        public int StatusBasicInfo { get; set; }
        public int StatusSectionName { get; set; }
        public ulong DeepAllocationBase { get; set; }
        public ulong DeepRegionSize { get; set; }
        public uint DeepRegionProtect { get; set; }
        public uint DeepRegionState { get; set; }
        public uint DeepRegionType { get; set; }
        public uint DeepSampleSize { get; set; }
        public byte[] DeepSample { get; set; } = Array.Empty<byte>();
        public string OriginPath { get; set; } = "";
        public uint CaptureFlags { get; set; }
        public uint FullFrameCount { get; set; }
        public ulong[] FullFrames { get; set; } = Array.Empty<ulong>();
        public ulong RegRax { get; set; }
        public ulong RegRbx { get; set; }
        public ulong RegRcx { get; set; }
        public ulong RegRdx { get; set; }
        public ulong RegRsi { get; set; }
        public ulong RegRdi { get; set; }
        public ulong RegRbp { get; set; }
        public ulong RegRsp { get; set; }
        public ulong RegR8 { get; set; }
        public ulong RegR9 { get; set; }
        public ulong RegR10 { get; set; }
        public ulong RegR11 { get; set; }
        public ulong RegR12 { get; set; }
        public ulong RegR13 { get; set; }
        public ulong RegR14 { get; set; }
        public ulong RegR15 { get; set; }
        public ulong RegRip { get; set; }
        public ulong RegEFlags { get; set; }
        public ulong RegDr0 { get; set; }
        public ulong RegDr1 { get; set; }
        public ulong RegDr2 { get; set; }
        public ulong RegDr3 { get; set; }
        public ulong RegDr6 { get; set; }
        public ulong RegDr7 { get; set; }
        public ulong StackSnapshotAddress { get; set; }
        public uint StackSnapshotSize { get; set; }
        public byte[] StackSnapshot { get; set; } = Array.Empty<byte>();

        public uint ProcessPid { get; set; }
        public uint ThreadId { get; set; }
        public uint CreatorPid { get; set; }
        public uint ThreadFlags { get; set; }
        public ulong StartAddress { get; set; }
        public ulong ImageBase { get; set; }
        public ulong ImageSize { get; set; }
        public uint ThreadFrameCount { get; set; }
        public ulong[] ThreadFrames { get; set; } = Array.Empty<ulong>();

        public uint FileProcessPid { get; set; }
        public uint FileThreadId { get; set; }
        public ulong FileObject { get; set; }
        public ulong FileId { get; set; }
        public ulong FileByteOffset { get; set; }
        public ulong FileLength { get; set; }
        public ulong FileStatus { get; set; }
        public ulong FileInformation { get; set; }
        public uint FileOperation { get; set; }
        public uint FileMajorCode { get; set; }
        public uint FileMinorCode { get; set; }
        public uint FileIrpFlags { get; set; }
        public uint FileCreateOptions { get; set; }
        public uint FileCreateDisposition { get; set; }
        public uint FileDesiredAccess { get; set; }
        public uint FileShareAccess { get; set; }
        public uint FileFlags { get; set; }
        public string FilePath { get; set; } = "";

        public IoctlParsedEvent Clone()
        {
            return new IoctlParsedEvent
            {
                Type = Type,
                Sequence = Sequence,
                StreamMask = StreamMask,
                CallerPid = CallerPid,
                TargetPid = TargetPid,
                DesiredAccess = DesiredAccess,
                HandleClass = HandleClass,
                HandleFlags = HandleFlags,
                OriginAddress = OriginAddress,
                OriginProtect = OriginProtect,
                FrameCount = FrameCount,
                Frames = Frames.ToArray(),
                StatusOpenProcess = StatusOpenProcess,
                StatusBasicInfo = StatusBasicInfo,
                StatusSectionName = StatusSectionName,
                DeepAllocationBase = DeepAllocationBase,
                DeepRegionSize = DeepRegionSize,
                DeepRegionProtect = DeepRegionProtect,
                DeepRegionState = DeepRegionState,
                DeepRegionType = DeepRegionType,
                DeepSampleSize = DeepSampleSize,
                DeepSample = DeepSample.ToArray(),
                OriginPath = OriginPath,
                CaptureFlags = CaptureFlags,
                FullFrameCount = FullFrameCount,
                FullFrames = FullFrames.ToArray(),
                RegRax = RegRax,
                RegRbx = RegRbx,
                RegRcx = RegRcx,
                RegRdx = RegRdx,
                RegRsi = RegRsi,
                RegRdi = RegRdi,
                RegRbp = RegRbp,
                RegRsp = RegRsp,
                RegR8 = RegR8,
                RegR9 = RegR9,
                RegR10 = RegR10,
                RegR11 = RegR11,
                RegR12 = RegR12,
                RegR13 = RegR13,
                RegR14 = RegR14,
                RegR15 = RegR15,
                RegRip = RegRip,
                RegEFlags = RegEFlags,
                RegDr0 = RegDr0,
                RegDr1 = RegDr1,
                RegDr2 = RegDr2,
                RegDr3 = RegDr3,
                RegDr6 = RegDr6,
                RegDr7 = RegDr7,
                StackSnapshotAddress = StackSnapshotAddress,
                StackSnapshotSize = StackSnapshotSize,
                StackSnapshot = StackSnapshot.ToArray(),
                ProcessPid = ProcessPid,
                ThreadId = ThreadId,
                CreatorPid = CreatorPid,
                ThreadFlags = ThreadFlags,
                StartAddress = StartAddress,
                ImageBase = ImageBase,
                ImageSize = ImageSize,
                ThreadFrameCount = ThreadFrameCount,
                ThreadFrames = ThreadFrames.ToArray(),
                FileProcessPid = FileProcessPid,
                FileThreadId = FileThreadId,
                FileObject = FileObject,
                FileId = FileId,
                FileByteOffset = FileByteOffset,
                FileLength = FileLength,
                FileStatus = FileStatus,
                FileInformation = FileInformation,
                FileOperation = FileOperation,
                FileMajorCode = FileMajorCode,
                FileMinorCode = FileMinorCode,
                FileIrpFlags = FileIrpFlags,
                FileCreateOptions = FileCreateOptions,
                FileCreateDisposition = FileCreateDisposition,
                FileDesiredAccess = FileDesiredAccess,
                FileShareAccess = FileShareAccess,
                FileFlags = FileFlags,
                FilePath = FilePath
            };
        }
    }

    internal sealed class BrokerEtwEventView
    {
        public DateTime TimestampUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public string Source { get; set; } = "";
        public uint Family { get; set; }
        public string EventName { get; set; } = "";
        public ushort Task { get; set; }
        public ushort Opcode { get; set; }
        public ushort EventId { get; set; }
        public uint EventProcessId { get; set; }
        public uint EventThreadId { get; set; }
        public uint Severity { get; set; }
        public uint Flags { get; set; }
        public uint ActorPid { get; set; }
        public uint TargetPid { get; set; }
        public uint ProcessPid { get; set; }
        public uint ThreadId { get; set; }
        public uint CallerPid { get; set; }
        public uint ExplicitTargetPid { get; set; }
        public uint ParentPid { get; set; }
        public uint CreatorPid { get; set; }
        public uint CreatorThreadId { get; set; }
        public uint CorrelationFlags { get; set; }
        public uint CorrelationAccessMask { get; set; }
        public uint CorrelationAgeMs { get; set; }
        public string DetectionName { get; set; } = "";
        public string Reason { get; set; } = "";
        public string ClassName { get; set; } = "";
        public string Operation { get; set; } = "";
        public uint DesiredAccess { get; set; }
        public ulong OriginAddress { get; set; }
        public uint OriginProtect { get; set; }
        public int StatusOpenProcess { get; set; }
        public int StatusBasicInfo { get; set; }
        public int StatusSectionName { get; set; }
        public uint StackCount { get; set; }
        public ulong[] Stack { get; set; } = Array.Empty<ulong>();
        public ulong DeepAllocationBase { get; set; }
        public ulong DeepRegionSize { get; set; }
        public uint DeepRegionProtect { get; set; }
        public uint DeepRegionState { get; set; }
        public uint DeepRegionType { get; set; }
        public uint DeepSampleSize { get; set; }
        public byte[] DeepSample { get; set; } = Array.Empty<byte>();
        public string OriginPath { get; set; } = "";
        public ulong StartAddress { get; set; }
        public ulong ImageBase { get; set; }
        public ulong ImageSize { get; set; }
        public uint StartRegionProtect { get; set; }
        public uint StartRegionState { get; set; }
        public uint StartRegionType { get; set; }
        public int StartRegionStatus { get; set; }
        public uint SessionId { get; set; }
        public int CreateStatus { get; set; }
        public ulong ProcessStartKey { get; set; }
        public byte SignatureLevel { get; set; }
        public byte SignatureType { get; set; }
        public uint NotifyClass { get; set; }
        public uint DataType { get; set; }
        public uint DataSize { get; set; }
        public string ImagePath { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public string KeyPath { get; set; } = "";
        public string ValueName { get; set; } = "";
        public int RepeatCount { get; set; } = 1;
        public string ArgumentSummary { get; set; } = string.Empty;

        public string Summary
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(DetectionName))
                {
                    return $"{DetectionName} (sev {Severity})";
                }

                if (!string.IsNullOrWhiteSpace(EventName))
                {
                    return $"{EventName} (sev {Severity})";
                }

                return $"telemetry (sev {Severity})";
            }
        }

        public string Details => BuildDetails();

        public BrokerEtwEventView Clone()
        {
            return new BrokerEtwEventView
            {
                TimestampUtc = TimestampUtc,
                LastSeenUtc = LastSeenUtc,
                Source = Source,
                Family = Family,
                EventName = EventName,
                Task = Task,
                Opcode = Opcode,
                EventId = EventId,
                EventProcessId = EventProcessId,
                EventThreadId = EventThreadId,
                Severity = Severity,
                Flags = Flags,
                ActorPid = ActorPid,
                TargetPid = TargetPid,
                ProcessPid = ProcessPid,
                ThreadId = ThreadId,
                CallerPid = CallerPid,
                ExplicitTargetPid = ExplicitTargetPid,
                ParentPid = ParentPid,
                CreatorPid = CreatorPid,
                CreatorThreadId = CreatorThreadId,
                CorrelationFlags = CorrelationFlags,
                CorrelationAccessMask = CorrelationAccessMask,
                CorrelationAgeMs = CorrelationAgeMs,
                DetectionName = DetectionName,
                Reason = Reason,
                ClassName = ClassName,
                Operation = Operation,
                DesiredAccess = DesiredAccess,
                OriginAddress = OriginAddress,
                OriginProtect = OriginProtect,
                StatusOpenProcess = StatusOpenProcess,
                StatusBasicInfo = StatusBasicInfo,
                StatusSectionName = StatusSectionName,
                StackCount = StackCount,
                Stack = Stack.ToArray(),
                DeepAllocationBase = DeepAllocationBase,
                DeepRegionSize = DeepRegionSize,
                DeepRegionProtect = DeepRegionProtect,
                DeepRegionState = DeepRegionState,
                DeepRegionType = DeepRegionType,
                DeepSampleSize = DeepSampleSize,
                DeepSample = DeepSample.ToArray(),
                OriginPath = OriginPath,
                StartAddress = StartAddress,
                ImageBase = ImageBase,
                ImageSize = ImageSize,
                StartRegionProtect = StartRegionProtect,
                StartRegionState = StartRegionState,
                StartRegionType = StartRegionType,
                StartRegionStatus = StartRegionStatus,
                SessionId = SessionId,
                CreateStatus = CreateStatus,
                ProcessStartKey = ProcessStartKey,
                SignatureLevel = SignatureLevel,
                SignatureType = SignatureType,
                NotifyClass = NotifyClass,
                DataType = DataType,
                DataSize = DataSize,
                ImagePath = ImagePath,
                CommandLine = CommandLine,
                KeyPath = KeyPath,
                ValueName = ValueName,
                RepeatCount = RepeatCount,
                ArgumentSummary = ArgumentSummary
            };
        }

        private string BuildDetails()
        {
            var sb = new StringBuilder(512);
            AppendToken(sb, $"source={Source}");
            AppendToken(sb, $"family={DescribeFamily(Family)}");
            AppendToken(sb, $"task={Task}");
            AppendToken(sb, $"opcode={Opcode}");
            AppendToken(sb, $"id={EventId}");
            AppendToken(sb, $"eventPid={EventProcessId}");
            AppendToken(sb, $"eventTid={EventThreadId}");
            AppendToken(sb, $"severity={Severity}");
            if (Flags != 0)
            {
                AppendToken(sb, $"flags=0x{Flags:X8}");
            }
            AppendToken(sb, $"actor={ActorPid}");
            AppendToken(sb, $"target={TargetPid}");
            if (ProcessPid != 0)
            {
                AppendToken(sb, $"process={ProcessPid}");
            }
            if (ThreadId != 0)
            {
                AppendToken(sb, $"thread={ThreadId}");
            }
            if (CallerPid != 0)
            {
                AppendToken(sb, $"caller={CallerPid}");
            }
            if (ExplicitTargetPid != 0)
            {
                AppendToken(sb, $"targetPid={ExplicitTargetPid}");
            }
            if (ParentPid != 0)
            {
                AppendToken(sb, $"parent={ParentPid}");
            }
            if (CreatorPid != 0)
            {
                AppendToken(sb, $"creator={CreatorPid}");
            }
            if (CreatorThreadId != 0)
            {
                AppendToken(sb, $"creatorThread={CreatorThreadId}");
            }
            if (!string.IsNullOrWhiteSpace(DetectionName))
            {
                AppendToken(sb, $"detection={DetectionName}");
            }
            if (DesiredAccess != 0)
            {
                AppendToken(sb, $"desiredAccess=0x{DesiredAccess:X8}");
            }
            if (CorrelationFlags != 0)
            {
                AppendToken(sb, $"corrFlags=0x{CorrelationFlags:X8}");
            }
            if (CorrelationAccessMask != 0)
            {
                AppendToken(sb, $"corrAccess=0x{CorrelationAccessMask:X8}");
            }
            if (CorrelationAgeMs != 0)
            {
                AppendToken(sb, $"corrAgeMs={CorrelationAgeMs}");
            }
            if (!string.IsNullOrWhiteSpace(ClassName))
            {
                AppendToken(sb, $"class={ClassName}");
            }
            if (!string.IsNullOrWhiteSpace(Operation))
            {
                AppendToken(sb, $"op={Operation}");
            }
            if (OriginAddress != 0)
            {
                AppendToken(sb, $"origin=0x{OriginAddress:X}");
            }
            if (OriginProtect != 0)
            {
                AppendToken(sb, $"originProtect=0x{OriginProtect:X8}");
            }
            if (StartAddress != 0)
            {
                AppendToken(sb, $"start=0x{StartAddress:X}");
            }
            if (ImageBase != 0 || ImageSize != 0)
            {
                AppendToken(sb, $"image=0x{ImageBase:X}/0x{ImageSize:X}");
            }
            if (!string.IsNullOrWhiteSpace(ImagePath))
            {
                AppendToken(sb, $"imagePath={ImagePath}");
            }
            if (!string.IsNullOrWhiteSpace(OriginPath))
            {
                AppendToken(sb, $"originPath={OriginPath}");
            }
            if (!string.IsNullOrWhiteSpace(CommandLine))
            {
                AppendToken(sb, $"commandLine={CommandLine}");
            }
            if (!string.IsNullOrWhiteSpace(KeyPath))
            {
                AppendToken(sb, $"key={KeyPath}");
            }
            if (!string.IsNullOrWhiteSpace(ValueName))
            {
                AppendToken(sb, $"value={ValueName}");
            }
            if (StatusOpenProcess != 0)
            {
                AppendToken(sb, $"statusOpenProcess=0x{unchecked((uint)StatusOpenProcess):X8}");
            }
            if (StatusBasicInfo != 0)
            {
                AppendToken(sb, $"statusBasicInfo=0x{unchecked((uint)StatusBasicInfo):X8}");
            }
            if (StatusSectionName != 0)
            {
                AppendToken(sb, $"statusSectionName=0x{unchecked((uint)StatusSectionName):X8}");
            }
            if (StackCount != 0)
            {
                AppendToken(sb, $"stackCount={StackCount}");
                int safeStackCount = Math.Min(Stack.Length, (int)StackCount);
                for (int i = 0; i < safeStackCount; i += 1)
                {
                    if (Stack[i] != 0)
                    {
                        AppendToken(sb, $"stack{i}=0x{Stack[i]:X}");
                    }
                }
            }
            if (DeepAllocationBase != 0)
            {
                AppendToken(sb, $"deepAllocationBase=0x{DeepAllocationBase:X}");
            }
            if (DeepRegionSize != 0)
            {
                AppendToken(sb, $"deepRegionSize=0x{DeepRegionSize:X}");
            }
            if (DeepRegionProtect != 0)
            {
                AppendToken(sb, $"deepRegionProtect=0x{DeepRegionProtect:X8}");
            }
            if (DeepRegionState != 0)
            {
                AppendToken(sb, $"deepRegionState=0x{DeepRegionState:X8}");
            }
            if (DeepRegionType != 0)
            {
                AppendToken(sb, $"deepRegionType=0x{DeepRegionType:X8}");
            }
            if (DeepSampleSize != 0)
            {
                AppendToken(sb, $"deepSampleSize={DeepSampleSize}");
                AppendToken(sb, $"deepSample={EventDetailFormatting.FormatSampleHex(DeepSample, (int)DeepSampleSize)}");
            }
            if (StartRegionProtect != 0)
            {
                AppendToken(sb, $"startRegionProtect=0x{StartRegionProtect:X8}");
            }
            if (StartRegionState != 0)
            {
                AppendToken(sb, $"startRegionState=0x{StartRegionState:X8}");
            }
            if (StartRegionType != 0)
            {
                AppendToken(sb, $"startRegionType=0x{StartRegionType:X8}");
            }
            if (StartRegionStatus != 0)
            {
                AppendToken(sb, $"startRegionStatus=0x{unchecked((uint)StartRegionStatus):X8}");
            }
            if (SessionId != 0)
            {
                AppendToken(sb, $"session={SessionId}");
            }
            if (CreateStatus != 0)
            {
                AppendToken(sb, $"createStatus=0x{unchecked((uint)CreateStatus):X8}");
            }
            if (ProcessStartKey != 0)
            {
                AppendToken(sb, $"processStartKey=0x{ProcessStartKey:X}");
            }
            if (SignatureLevel != 0)
            {
                AppendToken(sb, $"signatureLevel=0x{SignatureLevel:X2}");
            }
            if (SignatureType != 0)
            {
                AppendToken(sb, $"signatureType=0x{SignatureType:X2}");
            }
            if (NotifyClass != 0)
            {
                AppendToken(sb, $"notifyClass={NotifyClass}");
            }
            if (DataType != 0)
            {
                AppendToken(sb, $"dataType={DataType}");
            }
            if (DataSize != 0)
            {
                AppendToken(sb, $"dataSize={DataSize}");
            }
            if (!string.IsNullOrWhiteSpace(Reason))
            {
                AppendToken(sb, $"reason={Reason}");
            }
            AppendToken(sb, $"hits={Math.Max(1, RepeatCount)}");
            return sb.ToString();
        }

        private static void AppendToken(StringBuilder sb, string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return;
            }

            if (sb.Length > 0)
            {
                sb.Append(' ');
            }

            sb.Append(token);
        }

        private static string DescribeFamily(uint family)
        {
            return family switch
            {
                1 => "Handle",
                2 => "Thread",
                3 => "Process",
                4 => "Image",
                5 => "Registry",
                6 => "Apc",
                7 => "Detection",
                8 => "ThreatIntel",
                9 => "Socket",
                10 => "UserHook",
                _ => "Unknown"
            };
        }
    }

    internal sealed class HeuristicEventView
    {
        public DateTime TimestampUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public uint Severity { get; set; }
        public string DetectionName { get; set; } = "";
        public uint ActorPid { get; set; }
        public uint TargetPid { get; set; }
        public string Source { get; set; } = "";
        public string EventName { get; set; } = "";
        public uint CorrelationFlags { get; set; }
        public uint CorrelationAccessMask { get; set; }
        public uint CorrelationAgeMs { get; set; }
        public string Reason { get; set; } = "";
        public string Evidence { get; set; } = "";
        public int RepeatCount { get; set; } = 1;

        public string Summary => $"{DetectionName} (sev {Severity})";
        public string Details =>
            $"{Source}/{EventName} actor={ActorPid} target={TargetPid} corrFlags=0x{CorrelationFlags:X8} corrAccess=0x{CorrelationAccessMask:X8} corrAgeMs={CorrelationAgeMs} reason={Reason} evidence={Evidence} hits={Math.Max(1, RepeatCount)}";

        public HeuristicEventView Clone()
        {
            return new HeuristicEventView
            {
                TimestampUtc = TimestampUtc,
                LastSeenUtc = LastSeenUtc,
                Severity = Severity,
                DetectionName = DetectionName,
                ActorPid = ActorPid,
                TargetPid = TargetPid,
                Source = Source,
                EventName = EventName,
                CorrelationFlags = CorrelationFlags,
                CorrelationAccessMask = CorrelationAccessMask,
                CorrelationAgeMs = CorrelationAgeMs,
                Reason = Reason,
                Evidence = Evidence,
                RepeatCount = RepeatCount
            };
        }
    }

    internal sealed class ProcessRelationView
    {
        public DateTime FirstSeenUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public uint SourcePid { get; set; }
        public uint TargetPid { get; set; }
        public string RelationType { get; set; } = "";
        public uint LastAccessMask { get; set; }
        public uint LastFlags { get; set; }
        public int RepeatCount { get; set; } = 1;

        public string Summary => $"{RelationType} {SourcePid}->{TargetPid}";
        public string Details =>
            $"hits={Math.Max(1, RepeatCount)} access=0x{LastAccessMask:X8} flags=0x{LastFlags:X8}";

        public ProcessRelationView Clone()
        {
            return new ProcessRelationView
            {
                FirstSeenUtc = FirstSeenUtc,
                LastSeenUtc = LastSeenUtc,
                SourcePid = SourcePid,
                TargetPid = TargetPid,
                RelationType = RelationType,
                LastAccessMask = LastAccessMask,
                LastFlags = LastFlags,
                RepeatCount = RepeatCount
            };
        }
    }

    internal sealed class TiTaskCountView
    {
        public ushort Task { get; set; }
        public int Count { get; set; }
        public int MaxCount { get; set; }
        public string Label => Task == 0 ? "Task 0" : $"Task {Task}";

        public TiTaskCountView Clone()
        {
            return new TiTaskCountView
            {
                Task = Task,
                Count = Count,
                MaxCount = MaxCount
            };
        }
    }

    internal sealed class BackendStatsView
    {
        public DateTime TimestampUtc { get; set; }
        public uint SubscriptionCount { get; set; }
        public uint QueueDepth { get; set; }
        public uint DroppedEvents { get; set; }
    }

    internal sealed class BackendIpcDiagnosticsView
    {
        public DateTime TimestampUtc { get; set; }
        public uint BrokerCapabilities { get; set; }
        public bool SharedRingEnabled { get; set; }
        public uint SharedRingError { get; set; }
        public int IoctlReadBufferBytes { get; set; }
        public uint SubscriptionCount { get; set; }
        public uint DriverQueueDepth { get; set; }
        public uint DriverDroppedEvents { get; set; }
        public long IoctlEventsTotal { get; set; }
        public long EtwEventsTotal { get; set; }
        public long IoctlErrorsTotal { get; set; }
        public long EtwErrorsTotal { get; set; }
        public long IoctlEmptyPolls { get; set; }
        public long EtwEmptyPolls { get; set; }
        public double IoctlEventsPerSec { get; set; }
        public double EtwEventsPerSec { get; set; }
        public int PendingIoctlUiQueue { get; set; }
        public int PendingEtwUiQueue { get; set; }
        public int PendingStatusUiQueue { get; set; }
    }

    internal sealed class GroupedEventDetailRow : INotifyPropertyChanged
    {
        private DateTime _timestampUtc;
        private string _event = "";
        private string _severity = "";
        private string _detection = "";
        private string _source = "";
        private string _actor = "";
        private string _target = "";
        private uint _actorPid;
        private uint _targetPid;
        private string _actorToolTip = "";
        private string _targetToolTip = "";
        private string _argumentSummary = "";
        private string _details = "";
        private Dictionary<string, string>? _detailFields;

        public DateTime TimestampUtc
        {
            get => _timestampUtc;
            set => SetField(ref _timestampUtc, value);
        }

        public string Event
        {
            get => _event;
            set => SetField(ref _event, value ?? string.Empty);
        }

        public string Severity
        {
            get => _severity;
            set => SetField(ref _severity, value ?? string.Empty);
        }

        public string Detection
        {
            get => _detection;
            set => SetField(ref _detection, value ?? string.Empty);
        }

        public string Source
        {
            get => _source;
            set => SetField(ref _source, value ?? string.Empty);
        }

        public string Actor
        {
            get => _actor;
            set => SetField(ref _actor, value ?? string.Empty);
        }

        public string Target
        {
            get => _target;
            set => SetField(ref _target, value ?? string.Empty);
        }

        public uint ActorPid
        {
            get => _actorPid;
            set => SetField(ref _actorPid, value);
        }

        public uint TargetPid
        {
            get => _targetPid;
            set => SetField(ref _targetPid, value);
        }

        public string ActorToolTip
        {
            get => _actorToolTip;
            set => SetField(ref _actorToolTip, value ?? string.Empty);
        }

        public string TargetToolTip
        {
            get => _targetToolTip;
            set => SetField(ref _targetToolTip, value ?? string.Empty);
        }

        public string ArgumentSummary
        {
            get => _argumentSummary;
            set => SetField(ref _argumentSummary, value ?? string.Empty);
        }

        public string Details
        {
            get => _details;
            set
            {
                if (string.Equals(_details, value, StringComparison.Ordinal))
                {
                    return;
                }

                _details = value ?? string.Empty;
                _detailFields = null;
                OnPropertyChanged();
                OnPropertyChanged(nameof(EventPid));
                OnPropertyChanged(nameof(EventTid));
                OnPropertyChanged(nameof(Task));
                OnPropertyChanged(nameof(Opcode));
                OnPropertyChanged(nameof(EventId));
                OnPropertyChanged(nameof(Flags));
                OnPropertyChanged(nameof(Access));
                OnPropertyChanged(nameof(AgeMs));
                OnPropertyChanged(nameof(Reason));
                OnPropertyChanged(nameof(FilterText));
            }
        }

        [JsonIgnore]
        public string EventPid => GetDetailField("eventpid");

        [JsonIgnore]
        public string EventTid => GetDetailField("eventtid");

        [JsonIgnore]
        public string Task => GetDetailField("task");

        [JsonIgnore]
        public string Opcode => GetDetailField("opcode");

        [JsonIgnore]
        public string EventId => GetDetailField("id");

        [JsonIgnore]
        public string Flags => FirstNonEmpty(GetDetailField("corrflags"), GetDetailField("flags"));

        [JsonIgnore]
        public string Access => FirstNonEmpty(GetDetailField("corraccess"), GetDetailField("access"));

        [JsonIgnore]
        public string AgeMs => GetDetailField("corragems");

        [JsonIgnore]
        public string Reason => GetDetailField("reason");

        public string FilterText =>
            $"{TimestampUtc:O} {Event} {Severity} {Detection} {Source} {Actor} {Target} {ActorPid} {TargetPid} {ArgumentSummary} {Details} {EventPid} {EventTid} {Flags} {Access} {AgeMs} {Reason}";

        public GroupedEventDetailRow Clone()
        {
            return new GroupedEventDetailRow
            {
                TimestampUtc = TimestampUtc,
                Event = Event,
                Severity = Severity,
                Detection = Detection,
                Source = Source,
                Actor = Actor,
                Target = Target,
                ActorPid = ActorPid,
                TargetPid = TargetPid,
                ActorToolTip = ActorToolTip,
                TargetToolTip = TargetToolTip,
                ArgumentSummary = ArgumentSummary,
                Details = Details
            };
        }

        private static string FirstNonEmpty(string primary, string fallback)
        {
            if (!string.IsNullOrWhiteSpace(primary))
            {
                return primary;
            }

            return fallback;
        }

        private string GetDetailField(string key)
        {
            EnsureDetailFieldsParsed();
            if (_detailFields != null && _detailFields.TryGetValue(key, out string? value))
            {
                return value;
            }

            return string.Empty;
        }

        private void EnsureDetailFieldsParsed()
        {
            if (_detailFields != null)
            {
                return;
            }

            _detailFields = ParseDetailFields(_details);
        }

        private static Dictionary<string, string> ParseDetailFields(string details)
        {
            var parsed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(details))
            {
                return parsed;
            }

            string text = details.Trim();
            int index = 0;
            while (index < text.Length)
            {
                while (index < text.Length && char.IsWhiteSpace(text[index]))
                {
                    index += 1;
                }

                if (index >= text.Length)
                {
                    break;
                }

                int keyStart = index;
                while (index < text.Length && text[index] != '=' && !char.IsWhiteSpace(text[index]))
                {
                    index += 1;
                }

                if (index >= text.Length || text[index] != '=')
                {
                    while (index < text.Length && !char.IsWhiteSpace(text[index]))
                    {
                        index += 1;
                    }
                    continue;
                }

                string key = text[keyStart..index].Trim();
                index += 1;

                int valueStart = index;
                while (index < text.Length)
                {
                    if (!char.IsWhiteSpace(text[index]))
                    {
                        index += 1;
                        continue;
                    }

                    int probe = index;
                    while (probe < text.Length && char.IsWhiteSpace(text[probe]))
                    {
                        probe += 1;
                    }

                    if (probe >= text.Length)
                    {
                        index = probe;
                        break;
                    }

                    int nextKeyStart = probe;
                    while (probe < text.Length && text[probe] != '=' && !char.IsWhiteSpace(text[probe]))
                    {
                        probe += 1;
                    }

                    if (probe < text.Length && text[probe] == '=' && probe > nextKeyStart)
                    {
                        break;
                    }

                    index += 1;
                }

                string value = text[valueStart..index].Trim();
                if (!string.IsNullOrWhiteSpace(key))
                {
                    parsed[key] = value;
                }
            }

            return parsed;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
            {
                return false;
            }

            field = value;
            OnPropertyChanged(propertyName);
            return true;
        }

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    internal sealed class GroupedEventRow : INotifyPropertyChanged
    {
        private DateTime _lastSeenUtc;
        private string _event = "";
        private string _severity = "";
        private string _detection = "";
        private int _hits;
        private string _groupKey = "";

        public DateTime LastSeenUtc
        {
            get => _lastSeenUtc;
            set => SetField(ref _lastSeenUtc, value);
        }

        public string Event
        {
            get => _event;
            set => SetField(ref _event, value ?? string.Empty);
        }

        public string Severity
        {
            get => _severity;
            set => SetField(ref _severity, value ?? string.Empty);
        }

        public string Detection
        {
            get => _detection;
            set => SetField(ref _detection, value ?? string.Empty);
        }

        public int Hits
        {
            get => _hits;
            set => SetField(ref _hits, value);
        }

        public string GroupKey
        {
            get => _groupKey;
            set => SetField(ref _groupKey, value ?? string.Empty);
        }

        public List<GroupedEventDetailRow> Details { get; set; } = new();

        public GroupedEventRow Clone()
        {
            return new GroupedEventRow
            {
                LastSeenUtc = LastSeenUtc,
                Event = Event,
                Severity = Severity,
                Detection = Detection,
                Hits = Hits,
                GroupKey = GroupKey,
                Details = Details.Select(x => x.Clone()).ToList()
            };
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
            {
                return false;
            }

            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            return true;
        }
    }

    internal sealed class ApiCallGraphRowSnapshot
    {
        public string ApiName { get; set; } = "";
        public string SensorOrigin { get; set; } = "";
        public uint SourcePid { get; set; }
        public uint TargetPid { get; set; }
        public uint ThreadId { get; set; }
        public int Hits { get; set; }
        public DateTime LastSeenUtc { get; set; }
    }
}
