using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class PerformancePane
    {
        private void RefreshNetworkPeers(int targetPid)
        {
            List<NetworkPeerRow> rows = ReadNetworkPeers(targetPid);
            /* Preserve hook-driven rows that have bytes/source already filled in;
               merge netstat data so we don't lose them on each refresh tick. */
            var existingByKey = new Dictionary<string, NetworkPeerRow>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in NetworkPeers)
            {
                if (!string.IsNullOrEmpty(r.RemoteAddress))
                    existingByKey[$"{r.Protocol}|{r.RemoteEndpoint}"] = r;
            }

            NetworkPeers.Clear();
            _networkPeerByKey.Clear();
            foreach (NetworkPeerRow row in rows)
            {
                string key = $"{row.Protocol}|{row.RemoteEndpoint}";
                if (existingByKey.TryGetValue(key, out var existing))
                {
                    row.BytesSent = existing.BytesSent;
                    row.BytesRecv = existing.BytesRecv;
                    row.FirstSeen = existing.FirstSeen;
                    row.LastSeen = existing.LastSeen;
                    row.Source = existing.Source;
                    if (string.IsNullOrEmpty(row.DnsName) || row.DnsName == "-")
                        row.DnsName = existing.DnsName;
                }
                NetworkPeers.Add(row);
                _networkPeerByKey[key] = row;
            }
        }

        internal void IngestNetworkEvent(BlackbirdNative.BkIpcEtwEvent ev)
        {
            var view = new BrokerEtwEventView { Family = ev.Family,
                                                Source = ev.Source == BlackbirdNative.IpcEtwSourceKernelNetwork
                                                             ? "KernelNetwork"
                                                             : "UserHook",
                                                SourceId = ev.Source,
                                                Reason = BlackbirdNative.WideBufferToString(ev.Reason),
                                                Operation = BlackbirdNative.AnsiBufferToString(ev.Operation),
                                                ActorPid = ev.EventProcessId };
            IngestNetworkView(view);
        }

        internal void IngestNetworkView(BrokerEtwEventView view)
        {
            if (Dispatcher.CheckAccess())
            {
                IngestNetworkEventOnUiThread(view);
            }
            else
            {
                Dispatcher.InvokeAsync(() => IngestNetworkEventOnUiThread(view));
            }
        }

        private static (string ip, int port, string hostname, long bytes, bool isSend, bool isConnect)
            ParseNetworkReason(string reason)
        {
            string ip = "", hostname = "";
            int port = 0;
            long bytes = 0;
            bool isSend = false, isConnect = false;

            if (string.IsNullOrEmpty(reason))
                return (ip, port, hostname, bytes, isSend, isConnect);

            if (reason.Contains("socket.connect") || reason.Contains("kernel.net op=CONNECT") ||
                reason.Contains("KERNEL_NETWORK_CONNECT"))
                isConnect = true;

            if (reason.Contains("api=WSASend") || reason.Contains("api=send") || reason.Contains("kernel.net op=SEND"))
                isSend = true;

            foreach (string token in reason.Split(' '))
            {
                if (token.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                    ip = token.Substring(3);
                else if (token.StartsWith("dst=", StringComparison.OrdinalIgnoreCase))
                {
                    string dstPart = token.Substring(4);
                    int colon = dstPart.LastIndexOf(':');
                    if (colon >= 0)
                    {
                        ip = dstPart.Substring(0, colon);
                        int.TryParse(dstPart.Substring(colon + 1), out port);
                    }
                }
                else if (token.StartsWith("port=", StringComparison.OrdinalIgnoreCase))
                    int.TryParse(token.Substring(5), out port);
                else if (token.StartsWith("hostname=", StringComparison.OrdinalIgnoreCase))
                    hostname = token.Substring(9);
                else if (token.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase))
                    long.TryParse(token.Substring(6), out bytes);
            }

            return (ip, port, hostname, bytes, isSend, isConnect);
        }

        private void IngestNetworkEventOnUiThread(BrokerEtwEventView? ev)
        {
            if (ev == null)
                return;
            string reason = ev.Reason ?? string.Empty;
            var (ip, port, hostname, bytes, isSend, isConnect) = ParseNetworkReason(reason);

            if (string.IsNullOrEmpty(ip))
                return;

            string remoteEndpoint = port > 0 ? $"{ip}:{port}" : ip;
            string op = ev.Operation ?? string.Empty;
            string protocol = reason.Contains("UDP") || op == "SEND_UDP" || op == "RECV_UDP" ? "UDP" : "TCP";
            string sourceLabel = ev.SourceId == BlackbirdNative.IpcEtwSourceKernelNetwork ? "kernel" : "hook";
            string key = $"{protocol}|{remoteEndpoint}";

            if (_networkPeerByKey.Count != NetworkPeers.Count)
            {
                RebuildNetworkPeerIndex();
            }

            if (_networkPeerByKey.TryGetValue(key, out NetworkPeerRow? row))
            {
                row.ConnectionCount++;
                row.LastSeen = DateTime.UtcNow;
                if (isSend)
                    row.BytesSent += bytes;
                else if (!isConnect)
                    row.BytesRecv += bytes;
                if (string.IsNullOrEmpty(row.DnsName) || row.DnsName == "-")
                {
                    if (!string.IsNullOrEmpty(hostname))
                        row.DnsName = hostname;
                    else
                        row.DnsName = ResolveDnsName(ip);
                }
                return;
            }

            /* New endpoint */
            string dnsName = !string.IsNullOrEmpty(hostname) ? hostname : ResolveDnsName(ip);
            var newRow = new NetworkPeerRow { RemoteEndpoint = remoteEndpoint,
                                              RemoteAddress = ip,
                                              DnsName = dnsName,
                                              Protocol = protocol,
                                              State = isConnect ? "CONNECTED" : "ACTIVE",
                                              ConnectionCount = 1,
                                              BytesSent = isSend ? bytes : 0,
                                              BytesRecv = (!isConnect && !isSend) ? bytes : 0,
                                              FirstSeen = DateTime.UtcNow,
                                              LastSeen = DateTime.UtcNow,
                                              Source = sourceLabel };

            if (NetworkPeers.Count >= 512)
            {
                NetworkPeerRow removed = NetworkPeers[0];
                _networkPeerByKey.Remove($"{removed.Protocol}|{removed.RemoteEndpoint}");
                NetworkPeers.RemoveAt(0);
            }

            NetworkPeers.Add(newRow);
            _networkPeerByKey[key] = newRow;
        }

        private void RebuildNetworkPeerIndex()
        {
            _networkPeerByKey.Clear();
            foreach (NetworkPeerRow row in NetworkPeers)
            {
                if (!string.IsNullOrWhiteSpace(row.Protocol) && !string.IsNullOrWhiteSpace(row.RemoteEndpoint))
                {
                    _networkPeerByKey[$"{row.Protocol}|{row.RemoteEndpoint}"] = row;
                }
            }
        }

        private List<NetworkPeerRow> ReadNetworkPeers(int targetPid)
        {
            var rows = new Dictionary<string, NetworkPeerRow>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var psi = new ProcessStartInfo { FileName = "netstat",          Arguments = "-ano",
                                                 UseShellExecute = false,       RedirectStandardOutput = true,
                                                 RedirectStandardError = false, CreateNoWindow = true };

                using Process? process = Process.Start(psi);
                if (process == null)
                {
                    return new List<NetworkPeerRow>();
                }

                string ? line;
                while ((line = process.StandardOutput.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    string trimmed = line.Trim();
                    if (!trimmed.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                        !trimmed.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    string[] tokens = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (tokens.Length < 4)
                    {
                        continue;
                    }

                    string protocol = tokens[0].ToUpperInvariant();
                    string remoteEndpoint = tokens[2];
                    string state = protocol == "TCP" && tokens.Length >= 5 ? tokens[3] : "N/A";
                    string pidToken = protocol == "TCP" && tokens.Length >= 5 ? tokens[^1] : tokens[3];
                    if (!int.TryParse(pidToken, out int pid) || pid != targetPid)
                    {
                        continue;
                    }

                    string remoteAddress = ExtractAddress(remoteEndpoint);
                    if (remoteAddress.Length == 0 || remoteAddress == "*" || remoteAddress == "0.0.0.0" ||
                        remoteAddress == "::")
                    {
                        continue;
                    }

                    string key = $"{protocol}|{remoteAddress}|{state}";
                    if (!rows.TryGetValue(key, out NetworkPeerRow? row))
                    {
                        row = new NetworkPeerRow { LocalEndpoint = tokens[1],
                                                   RemoteEndpoint = remoteEndpoint,
                                                   RemoteAddress = remoteAddress,
                                                   Protocol = protocol,
                                                   State = state,
                                                   DnsName = ResolveDnsName(remoteAddress, allowBlocking: true),
                                                   ConnectionCount = 1 };
                        rows[key] = row;
                    }
                    else
                    {
                        row.ConnectionCount += 1;
                    }
                }
            }
            catch
            {
                return new List<NetworkPeerRow>();
            }

            return rows.Values.OrderByDescending(x => x.ConnectionCount)
                .ThenBy(x => x.RemoteAddress, StringComparer.OrdinalIgnoreCase)
                .Take(128)
                .ToList();
        }

        private string ResolveDnsName(string remoteAddress, bool allowBlocking = false)
        {
            if (_reverseDnsCache.TryGetValue(remoteAddress, out string? cached))
            {
                return cached;
            }

            if (!IPAddress.TryParse(remoteAddress, out IPAddress? ip) ||
                IPAddress.IsLoopback(ip))
            {
                _reverseDnsCache[remoteAddress] = "-";
                return "-";
            }

            if (!allowBlocking)
            {
                QueueReverseDnsLookup(remoteAddress);
                return "-";
            }

            string host = "-";
            try
            {
                var lookup = System.Threading.Tasks.Task.Run(() => Dns.GetHostEntry(remoteAddress));
                _ = lookup.ContinueWith(static task =>
                                        { _ = task.Exception; },
                                        System.Threading.Tasks.TaskContinuationOptions.OnlyOnFaulted);
                if (lookup.Wait(120) && lookup.Result != null)
                {
                    host = string.IsNullOrWhiteSpace(lookup.Result.HostName) ? remoteAddress : lookup.Result.HostName;
                }
            }
            catch
            {
                host = "-";
            }

            _reverseDnsCache[remoteAddress] = host;
            return host;
        }

        private void QueueReverseDnsLookup(string remoteAddress)
        {
            if (!_pendingReverseDnsLookups.Add(remoteAddress))
            {
                return;
            }

            _ = System.Threading.Tasks.Task.Run(
                () =>
                {
                    string host = "-";
                    try
                    {
                        IPHostEntry entry = Dns.GetHostEntry(remoteAddress);
                        host = string.IsNullOrWhiteSpace(entry.HostName) ? remoteAddress : entry.HostName;
                    }
                    catch
                    {
                        host = "-";
                    }

                    Dispatcher.BeginInvoke(
                        new Action(() =>
                                   {
                                       _pendingReverseDnsLookups.Remove(remoteAddress);
                                       _reverseDnsCache[remoteAddress] = host;
                                       bool changed = false;
                                       foreach (NetworkPeerRow row in NetworkPeers)
                                       {
                                           if (string.Equals(row.RemoteAddress, remoteAddress,
                                                             StringComparison.OrdinalIgnoreCase) &&
                                               (string.IsNullOrEmpty(row.DnsName) || row.DnsName == "-"))
                                           {
                                               row.DnsName = host;
                                               changed = true;
                                           }
                                       }

                                       if (changed)
                                       {
                                           NetworkPeersGrid?.Items.Refresh();
                                       }
                                   }));
                });
        }

        private static string ExtractAddress(string endpoint)
        {
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return string.Empty;
            }

            string value = endpoint.Trim();
            if (value.StartsWith("[", StringComparison.Ordinal))
            {
                int close = value.IndexOf(']');
                if (close > 1)
                {
                    return value[1..close];
                }
            }

            int lastColon = value.LastIndexOf(':');
            if (lastColon > 0)
            {
                return value[..lastColon];
            }

            return value;
        }
    }
}
