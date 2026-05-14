namespace BlackbirdInterface
{
    public sealed class StackFrameRow
    {
        public int Index { get; set; }
        public string Address { get; set; } = string.Empty;
        public string Module { get; set; } = string.Empty;
        public string Symbol { get; set; } = string.Empty;
        public ulong InstructionPointerRaw { get; set; }
        public ulong FramePointerRaw { get; set; }
        public long FrameSpanBytes { get; set; }
        public bool IsCurrent { get; set; }
        public string FramePointer => FramePointerRaw == 0 ? "N/A" : $"0x{FramePointerRaw:X}";
        public string FrameSpan => FrameSpanBytes > 0 ? $"0x{FrameSpanBytes:X}" : "N/A";

        public StackFrameRow Clone()
        {
            return new StackFrameRow { Index = Index,
                                       Address = Address,
                                       Module = Module,
                                       Symbol = Symbol,
                                       InstructionPointerRaw = InstructionPointerRaw,
                                       FramePointerRaw = FramePointerRaw,
                                       FrameSpanBytes = FrameSpanBytes,
                                       IsCurrent = IsCurrent };
        }
    }
}
