using System;

namespace SleepwalkerInterface
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

        public uint ProcessPid { get; set; }
        public uint ThreadId { get; set; }
        public uint CreatorPid { get; set; }
        public uint ThreadFlags { get; set; }
        public ulong StartAddress { get; set; }
        public ulong ImageBase { get; set; }
        public ulong ImageSize { get; set; }
    }

    internal sealed class BrokerEtwEventView
    {
        public DateTime TimestampUtc { get; set; }
        public string Source { get; set; } = "";
        public string EventName { get; set; } = "";
        public ushort Task { get; set; }
        public ushort Opcode { get; set; }
        public ushort EventId { get; set; }
        public uint EventProcessId { get; set; }
        public uint EventThreadId { get; set; }
        public uint Severity { get; set; }
        public uint ActorPid { get; set; }
        public uint TargetPid { get; set; }
        public string DetectionName { get; set; } = "";

        public string Summary
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(DetectionName))
                {
                    return $"{DetectionName} (sev {Severity})";
                }

                return $"task={Task} opcode={Opcode} id={EventId}";
            }
        }

        public string Details =>
            $"eventPid={EventProcessId} eventTid={EventThreadId} actor={ActorPid} target={TargetPid}";

        public BrokerEtwEventView Clone()
        {
            return new BrokerEtwEventView
            {
                TimestampUtc = TimestampUtc,
                Source = Source,
                EventName = EventName,
                Task = Task,
                Opcode = Opcode,
                EventId = EventId,
                EventProcessId = EventProcessId,
                EventThreadId = EventThreadId,
                Severity = Severity,
                ActorPid = ActorPid,
                TargetPid = TargetPid,
                DetectionName = DetectionName
            };
        }
    }

    internal sealed class HeuristicEventView
    {
        public DateTime TimestampUtc { get; set; }
        public uint Severity { get; set; }
        public string DetectionName { get; set; } = "";
        public uint ActorPid { get; set; }
        public uint TargetPid { get; set; }
        public string Source { get; set; } = "";
        public string EventName { get; set; } = "";

        public string Summary => $"{DetectionName} (sev {Severity})";
        public string Details => $"{Source}/{EventName} actor={ActorPid} target={TargetPid}";

        public HeuristicEventView Clone()
        {
            return new HeuristicEventView
            {
                TimestampUtc = TimestampUtc,
                Severity = Severity,
                DetectionName = DetectionName,
                ActorPid = ActorPid,
                TargetPid = TargetPid,
                Source = Source,
                EventName = EventName
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
}
