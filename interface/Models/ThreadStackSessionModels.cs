using System;
using System.Collections.Generic;
using System.Linq;

namespace BlackbirdInterface
{
    public sealed class ThreadStackHistoryArchiveEntry
    {
        public int Tid { get; set; }
        public string State { get; set; } = string.Empty;
        public List<ThreadStackSessionSnapshot> Snapshots { get; set; } = new();

        public ThreadStackHistoryArchiveEntry Clone()
        {
            return new ThreadStackHistoryArchiveEntry
            {
                Tid = Tid,
                State = State,
                Snapshots = Snapshots.Select(x => x.Clone()).ToList()
            };
        }
    }

    public sealed class ThreadStackSessionSnapshot
    {
        public DateTime CapturedAtUtc { get; set; }
        public ulong TebAddress { get; set; }
        public ulong StackBase { get; set; }
        public ulong StackTop { get; set; }
        public ushort? TebFlags { get; set; }
        public ulong StackPointer { get; set; }
        public ThreadContextSnapshot? ContextSnapshot { get; set; }
        public List<StackFrameRow> Frames { get; set; } = new();

        public ThreadStackSessionSnapshot Clone()
        {
            return new ThreadStackSessionSnapshot
            {
                CapturedAtUtc = CapturedAtUtc,
                TebAddress = TebAddress,
                StackBase = StackBase,
                StackTop = StackTop,
                TebFlags = TebFlags,
                StackPointer = StackPointer,
                ContextSnapshot = CloneContext(ContextSnapshot),
                Frames = Frames.Select(CloneFrame).ToList()
            };
        }

        private static StackFrameRow CloneFrame(StackFrameRow frame)
        {
            return new StackFrameRow
            {
                Index = frame.Index,
                Address = frame.Address,
                Module = frame.Module,
                Symbol = frame.Symbol,
                InstructionPointerRaw = frame.InstructionPointerRaw,
                FramePointerRaw = frame.FramePointerRaw,
                FrameSpanBytes = frame.FrameSpanBytes,
                IsCurrent = frame.IsCurrent
            };
        }

        private static ThreadContextSnapshot? CloneContext(ThreadContextSnapshot? snapshot)
        {
            if (snapshot == null)
            {
                return null;
            }

            return new ThreadContextSnapshot
            {
                Rip = snapshot.Rip,
                Rsp = snapshot.Rsp,
                Rbp = snapshot.Rbp,
                Rax = snapshot.Rax,
                Rbx = snapshot.Rbx,
                Rcx = snapshot.Rcx,
                Rdx = snapshot.Rdx,
                Rsi = snapshot.Rsi,
                Rdi = snapshot.Rdi,
                R8 = snapshot.R8,
                R9 = snapshot.R9,
                R10 = snapshot.R10,
                R11 = snapshot.R11,
                R12 = snapshot.R12,
                R13 = snapshot.R13,
                R14 = snapshot.R14,
                R15 = snapshot.R15,
                Dr0 = snapshot.Dr0,
                Dr1 = snapshot.Dr1,
                Dr2 = snapshot.Dr2,
                Dr3 = snapshot.Dr3,
                Dr6 = snapshot.Dr6,
                Dr7 = snapshot.Dr7,
                EFlags = snapshot.EFlags
            };
        }
    }
}


