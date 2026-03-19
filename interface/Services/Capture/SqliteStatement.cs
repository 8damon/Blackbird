#nullable enable

using System;
using System.Runtime.InteropServices;

namespace BlackbirdInterface.Capture
{
    internal enum SqliteStepState
    {
        Done = 0,
        Row = 1
    }

    internal sealed class SqliteStatement : IDisposable
    {
        private readonly SqliteDatabase _database;
        private IntPtr _statement;
        private bool _disposed;

        internal SqliteStatement(SqliteDatabase database, IntPtr statement)
        {
            _database = database ?? throw new ArgumentNullException(nameof(database));
            _statement = statement;
        }

        internal int ColumnCount
        {
            get
            {
                EnsureOpen();
                return SqliteNative.sqlite3_column_count(_statement);
            }
        }

        internal void BindInt64(int index, long value)
        {
            EnsureOpen();
            _database.ThrowIfError(SqliteNative.sqlite3_bind_int64(_statement, index, value), "sqlite3_bind_int64 failed");
        }

        internal void BindText(int index, string? value)
        {
            EnsureOpen();
            if (value == null)
            {
                BindNull(index);
                return;
            }

            int bytes = checked(value.Length * sizeof(char));
            _database.ThrowIfError(
                SqliteNative.sqlite3_bind_text16(_statement, index, value, bytes, SqliteNative.Transient),
                "sqlite3_bind_text16 failed");
        }

        internal void BindBlob(int index, byte[]? value)
        {
            EnsureOpen();
            if (value == null)
            {
                BindNull(index);
                return;
            }

            _database.ThrowIfError(
                SqliteNative.sqlite3_bind_blob(_statement, index, value, value.Length, SqliteNative.Transient),
                "sqlite3_bind_blob failed");
        }

        internal void BindNull(int index)
        {
            EnsureOpen();
            _database.ThrowIfError(SqliteNative.sqlite3_bind_null(_statement, index), "sqlite3_bind_null failed");
        }

        internal SqliteStepState Step()
        {
            EnsureOpen();
            int rc = SqliteNative.sqlite3_step(_statement);
            return rc switch
            {
                SqliteNative.Row => SqliteStepState.Row,
                SqliteNative.Done => SqliteStepState.Done,
                _ => throw BuildStepException(rc)
            };
        }

        internal void Reset()
        {
            EnsureOpen();
            _database.ThrowIfError(SqliteNative.sqlite3_reset(_statement), "sqlite3_reset failed");
        }

        internal void ClearBindings()
        {
            EnsureOpen();
            _database.ThrowIfError(SqliteNative.sqlite3_clear_bindings(_statement), "sqlite3_clear_bindings failed");
        }

        internal long ReadInt64(int column)
        {
            EnsureOpen();
            return SqliteNative.sqlite3_column_int64(_statement, column);
        }

        internal string? ReadText(int column)
        {
            EnsureOpen();
            if (SqliteNative.sqlite3_column_type(_statement, column) == SqliteNative.Null)
            {
                return null;
            }

            IntPtr pointer = SqliteNative.sqlite3_column_text16(_statement, column);
            if (pointer == IntPtr.Zero)
            {
                return string.Empty;
            }

            int bytes = SqliteNative.sqlite3_column_bytes16(_statement, column);
            return bytes <= 0 ? string.Empty : Marshal.PtrToStringUni(pointer, bytes / sizeof(char));
        }

        internal byte[]? ReadBlob(int column)
        {
            EnsureOpen();
            if (SqliteNative.sqlite3_column_type(_statement, column) == SqliteNative.Null)
            {
                return null;
            }

            IntPtr pointer = SqliteNative.sqlite3_column_blob(_statement, column);
            int bytes = SqliteNative.sqlite3_column_bytes(_statement, column);
            if (pointer == IntPtr.Zero || bytes <= 0)
            {
                return Array.Empty<byte>();
            }

            byte[] buffer = new byte[bytes];
            Marshal.Copy(pointer, buffer, 0, bytes);
            return buffer;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            IntPtr statement = _statement;
            _statement = IntPtr.Zero;
            if (statement != IntPtr.Zero)
            {
                _database.ThrowIfError(SqliteNative.sqlite3_finalize(statement), "sqlite3_finalize failed");
            }

            GC.SuppressFinalize(this);
        }

        private Exception BuildStepException(int rc)
        {
            try
            {
                _database.ThrowIfError(rc, "sqlite3_step failed");
                return new InvalidOperationException("sqlite3_step failed");
            }
            catch (Exception ex)
            {
                return ex;
            }
        }

        private void EnsureOpen()
        {
            if (_disposed || _statement == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(SqliteStatement));
            }
        }
    }
}

