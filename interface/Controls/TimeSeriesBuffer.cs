using System;
using System.Collections.Generic;

namespace BlackbirdInterface
{
    public sealed class TimeSeriesBuffer
    {
        private readonly int _max;
        private readonly List<(DateTime t, double v)> _items = new();

        public TimeSeriesBuffer(int max)
        {
            _max = Math.Max(10, max);
        }

        public void Add(DateTime t, double v)
        {
            _items.Add((t, v));
            if (_items.Count > _max)
                _items.RemoveRange(0, _items.Count - _max);
        }

        public IReadOnlyList<(DateTime t, double v)> Items => _items;
    }
}

