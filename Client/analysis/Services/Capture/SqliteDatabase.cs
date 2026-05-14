#nullable enable

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace BlackbirdInterface.Capture
{
    internal sealed class SqliteDatabase : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        private SqliteDatabase(IntPtr handle, string path)
        {
            _handle = handle;
            Path = path;
        }

        internal string Path { get; }

        internal static SqliteDatabase Open(string path, bool createIfMissing = true)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Database path is required.", nameof(path));
            }

            string fullPath = System.IO.Path.GetFullPath(path);
            string? directory = System.IO.Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            if (!createIfMissing && !File.Exists(fullPath))
            {
                throw new FileNotFoundException("SQLite database not found.", fullPath);
            }

            int flags = SqliteNative.OpenReadWrite | SqliteNative.OpenNoMutex | SqliteNative.OpenPrivateCache;
            if (createIfMissing)
            {
                flags |= SqliteNative.OpenCreate;
            }

            int rc = SqliteNative.sqlite3_open_v2(ToUtf8Z(fullPath), out IntPtr handle, flags, IntPtr.Zero);
            if (rc != SqliteNative.Ok)
            {
                string message = TryGetError(handle) ?? "sqlite3_open_v2 failed";
                if (handle != IntPtr.Zero)
                {
                    _ = SqliteNative.sqlite3_close_v2(handle);
                }

                throw new SqliteException(message, rc);
            }

            return new SqliteDatabase(handle, fullPath);
        }

        internal void ExecuteNonQuery(string sql)
        {
            EnsureOpen();
            if (string.IsNullOrWhiteSpace(sql))
            {
                return;
            }

            int rc =
                SqliteNative.sqlite3_exec(_handle, ToUtf8Z(sql), IntPtr.Zero, IntPtr.Zero, out IntPtr errorMessage);
            if (rc == SqliteNative.Ok)
            {
                return;
            }

            string message = errorMessage != IntPtr.Zero ? MarshalSqliteStringAndFree(errorMessage)
                                                         : (TryGetError(_handle) ?? "sqlite3_exec failed");
            throw new SqliteException(message, rc);
        }

        internal SqliteStatement Prepare(string sql)
        {
            EnsureOpen();
            if (string.IsNullOrWhiteSpace(sql))
            {
                throw new ArgumentException("SQL text is required.", nameof(sql));
            }

            int rc = SqliteNative.sqlite3_prepare16_v2(_handle, sql, -1, out IntPtr statement, out _);
            if (rc != SqliteNative.Ok || statement == IntPtr.Zero)
            {
                throw BuildException(rc, "sqlite3_prepare16_v2 failed");
            }

            return new SqliteStatement(this, statement);
        }

        internal void ThrowIfError(int resultCode, string operation)
        {
            if (resultCode == SqliteNative.Ok || resultCode == SqliteNative.Row || resultCode == SqliteNative.Done)
            {
                return;
            }

            throw BuildException(resultCode, operation);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            IntPtr handle = _handle;
            _handle = IntPtr.Zero;
            if (handle != IntPtr.Zero)
            {
                int rc = SqliteNative.sqlite3_close_v2(handle);
                if (rc != SqliteNative.Ok)
                {
                    throw new SqliteException("sqlite3_close_v2 failed", rc);
                }
            }

            GC.SuppressFinalize(this);
        }

        internal IntPtr Handle
        {
            get {
                EnsureOpen();
                return _handle;
            }
        }

        private SqliteException BuildException(int resultCode, string operation)
        {
            int code = resultCode != SqliteNative.Ok
                           ? resultCode
                           : (_handle == IntPtr.Zero ? resultCode : SqliteNative.sqlite3_extended_errcode(_handle));
            string message = TryGetError(_handle) ?? operation;
            return new SqliteException(message, code);
        }

        private void EnsureOpen()
        {
            if (_disposed || _handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(SqliteDatabase));
            }
        }

        private static string? TryGetError(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                return null;
            }

            IntPtr messagePtr = SqliteNative.sqlite3_errmsg16(handle);
            return messagePtr == IntPtr.Zero ? null : Marshal.PtrToStringUni(messagePtr);
        }

        private static string MarshalSqliteStringAndFree(IntPtr pointer)
        {
            try
            {
                return pointer == IntPtr.Zero ? "sqlite error" : (Marshal.PtrToStringUTF8(pointer) ?? "sqlite error");
            }
            finally
            {
                if (pointer != IntPtr.Zero)
                {
                    SqliteNative.sqlite3_free(pointer);
                }
            }
        }

        private static byte[] ToUtf8Z(string value)
        {
            byte[] data = Encoding.UTF8.GetBytes(value);
            byte[] buffer = new byte[data.Length + 1];
            Buffer.BlockCopy(data, 0, buffer, 0, data.Length);
            return buffer;
        }
    }
}
