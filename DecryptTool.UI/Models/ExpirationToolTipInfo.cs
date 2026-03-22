using System.Windows.Media;

namespace DecryptTool.UI.Models;

public sealed class ExpirationToolTipInfo
{
    public string Header { get; init; } = "exp";

    public string StatusText { get; init; } = string.Empty;

    public Brush StatusBrush { get; init; } = Brushes.Gray;

    public string ExpiresLocalText { get; init; } = "Not present";

    public string ExpiresUtcText { get; init; } = "Not present";

    public string RemainingText { get; init; } = "Unknown";

    public string TokenLifetimeText { get; init; } = "Unknown";
}
