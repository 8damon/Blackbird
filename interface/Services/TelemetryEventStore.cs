using System;
using System.Collections;
using System.Collections.Generic;

namespace BlackbirdInterface
{
    internal sealed class TelemetryEventStore : IReadOnlyList<TelemetryEvent>
    {
        private const int ChunkCapacity = 512;

        private readonly List<Chunk> _chunks = new();
        private int _count;

        public int Count => _count;

        public TelemetryEvent this[int index]
        {
            get
            {
                if ((uint)index >= (uint)_count)
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }

                int remaining = index;
                for (int i = 0; i < _chunks.Count; i += 1)
                {
                    Chunk chunk = _chunks[i];
                    if (remaining < chunk.Count)
                    {
                        return chunk.Items[chunk.Start + remaining]!;
                    }

                    remaining -= chunk.Count;
                }

                throw new ArgumentOutOfRangeException(nameof(index));
            }
        }

        public TelemetryEvent this[Index index] => this[index.GetOffset(_count)];

        public void Add(TelemetryEvent item)
        {
            if (_chunks.Count == 0)
            {
                _chunks.Add(new Chunk());
            }

            Chunk tail = _chunks[^1];
            if (tail.Start + tail.Count >= ChunkCapacity)
            {
                tail = new Chunk();
                _chunks.Add(tail);
            }

            tail.Items[tail.Start + tail.Count] = item;
            tail.Count += 1;
            _count += 1;
        }

        public void AddRange(IEnumerable<TelemetryEvent> items)
        {
            foreach (TelemetryEvent item in items)
            {
                Add(item);
            }
        }

        public void Clear()
        {
            _chunks.Clear();
            _count = 0;
        }

        public void RemoveFirst(int count)
        {
            if (count <= 0 || _count == 0)
            {
                return;
            }

            int remaining = Math.Min(count, _count);
            while (remaining > 0 && _chunks.Count > 0)
            {
                Chunk head = _chunks[0];
                int remove = Math.Min(remaining, head.Count);
                Array.Clear(head.Items, head.Start, remove);
                head.Start += remove;
                head.Count -= remove;
                _count -= remove;
                remaining -= remove;

                if (head.Count == 0)
                {
                    _chunks.RemoveAt(0);
                }
            }
        }

        public IEnumerator<TelemetryEvent> GetEnumerator()
        {
            for (int i = 0; i < _chunks.Count; i += 1)
            {
                Chunk chunk = _chunks[i];
                for (int j = 0; j < chunk.Count; j += 1)
                {
                    yield return chunk.Items[chunk.Start + j]!;
                }
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private sealed class Chunk
        {
            public TelemetryEvent?[] Items { get; } = new TelemetryEvent[ChunkCapacity];
            public int Start { get; set; }
            public int Count { get; set; }
        }
    }
}
