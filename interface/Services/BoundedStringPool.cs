using System;
using System.Collections.Generic;

namespace BlackbirdInterface
{
    internal sealed class BoundedStringPool
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
        private readonly int _maxEntries;

        public BoundedStringPool(int maxEntries)
        {
            _maxEntries = maxEntries < 64 ? 64 : maxEntries;
        }

        public int Count => _values.Count;

        public string Intern(string? value, int maxLength)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            if (value.Length > maxLength)
            {
                return value;
            }

            if (_values.TryGetValue(value, out string? existing))
            {
                return existing;
            }

            if (_values.Count >= _maxEntries)
            {
                return value;
            }

            _values[value] = value;
            return value;
        }

        public void Clear()
        {
            _values.Clear();
        }
    }
}
