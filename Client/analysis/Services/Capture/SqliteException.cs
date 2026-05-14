#nullable enable

using System;

namespace BlackbirdInterface.Capture
{
    internal sealed class SqliteException : InvalidOperationException
    {
        internal SqliteException(string message, int resultCode) : base($"{message} (sqlite={resultCode})")
        {
            ResultCode = resultCode;
        }

        internal int ResultCode { get; }
    }
}
