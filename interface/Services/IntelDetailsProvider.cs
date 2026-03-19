using System.Collections.Generic;

namespace BlackbirdInterface
{
    internal enum IntelDetailsCategory
    {
        Etw,
        Heuristics,
        Filesystem,
        ProcessRelations
    }

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

