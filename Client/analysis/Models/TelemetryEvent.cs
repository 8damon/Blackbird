using System;

namespace BlackbirdInterface
{
    public sealed class TelemetryEvent
    {
        public DateTime TimestampUtc { get; init; }

        public int PID { get; init; }
        public int TID { get; init; }

        // Example: Group="Execution", SubType="CreateProcess"
        public string Group { get; init; } = "Other";
        public string SubType { get; init; } = "";

        // Backward compat if you still set Type only.
        public string Type
        {
            get {
                if (string.IsNullOrWhiteSpace(SubType))
                    return Group;
                return $"{Group}/{SubType}";
            }
        }

        public string ProcessName { get; init; } = "";

        public string Summary { get; init; } = "";
        public string Details { get; init; } = "";
    }
}
