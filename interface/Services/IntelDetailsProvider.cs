using System.Collections.Generic;

namespace SleepwalkerInterface
{
    internal enum IntelScopeStatus
    {
        Unknown,
        Running,
        Waiting,
        Exited
    }

    internal interface IIntelDetailsProvider
    {
        IReadOnlyList<GroupedEventDetailRow> GetIntelDetails(IntelDetailsCategory category);
        string GetIntelScopeLabel();
        IntelScopeStatus GetIntelScopeStatus();
    }
}
