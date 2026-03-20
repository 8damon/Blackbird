using System.IO;
using System.Text.Json;
using BlackbirdOperator.Models;

namespace BlackbirdOperator.Services;

public static class OperatorConfigStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public static string ConfigDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Blackbird",
        "Operator");

    public static string ConfigPath => Path.Combine(ConfigDirectory, "config.json");
    public static bool HasSavedConfig => File.Exists(ConfigPath);

    public static OperatorDiscoveryOptions LoadOrDefault()
    {
        try
        {
            if (!File.Exists(ConfigPath))
            {
                return new OperatorDiscoveryOptions();
            }

            string json = File.ReadAllText(ConfigPath);
            return JsonSerializer.Deserialize<OperatorDiscoveryOptions>(json, JsonOptions) ?? new OperatorDiscoveryOptions();
        }
        catch
        {
            return new OperatorDiscoveryOptions();
        }
    }

    public static void Save(OperatorDiscoveryOptions options)
    {
        Directory.CreateDirectory(ConfigDirectory);
        string json = JsonSerializer.Serialize(options, JsonOptions);
        File.WriteAllText(ConfigPath, json);
    }

    public static void Reset()
    {
        if (File.Exists(ConfigPath))
        {
            File.Delete(ConfigPath);
        }
    }
}
