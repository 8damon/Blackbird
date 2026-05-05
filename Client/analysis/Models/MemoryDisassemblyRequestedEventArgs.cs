using System;

namespace BlackbirdInterface
{
    public sealed class MemoryDisassemblyRequestedEventArgs : EventArgs
    {
        public uint ProcessId { get; }
        public ulong BaseAddress { get; }
        public ulong RegionSize { get; }
        public string Label { get; }
        public byte[]? SnapshotBytes { get; }
        public uint SnapshotOffset { get; }

        public MemoryDisassemblyRequestedEventArgs(uint processId, ulong baseAddress, ulong regionSize, string label,
                                                   byte[]? snapshotBytes = null, uint snapshotOffset = 0)
        {
            ProcessId = processId;
            BaseAddress = baseAddress;
            RegionSize = regionSize;
            Label = label;
            SnapshotBytes = snapshotBytes?.ToArray();
            SnapshotOffset = snapshotOffset;
        }
    }
}
