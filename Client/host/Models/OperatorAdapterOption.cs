namespace BlackbirdOperator.Models;

public sealed class OperatorAdapterOption
{
    public string InterfaceId { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Address { get; init; } = string.Empty;
    public string Prefix { get; init; } = string.Empty;
    public string Summary => string.IsNullOrWhiteSpace(Name) ? $"{Address}/{Prefix}" : $"{Name}  {Address}/{Prefix}";
}
