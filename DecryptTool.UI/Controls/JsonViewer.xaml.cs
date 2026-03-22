using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using DecryptTool.UI.Models;

namespace DecryptTool.UI.Controls;

public partial class JsonViewer : UserControl
{
    public static readonly DependencyProperty JsonTextProperty =
        DependencyProperty.Register(nameof(JsonText), typeof(string), typeof(JsonViewer), new PropertyMetadata(string.Empty, OnJsonTextChanged));

    public static readonly DependencyProperty ExpirationInfoProperty =
        DependencyProperty.Register(nameof(ExpirationInfo), typeof(ExpirationToolTipInfo), typeof(JsonViewer), new PropertyMetadata(null, OnJsonTextChanged));

    public static readonly DependencyProperty ViewerFontFamilyProperty =
        DependencyProperty.Register(nameof(ViewerFontFamily), typeof(FontFamily), typeof(JsonViewer), new PropertyMetadata(new FontFamily("Consolas"), OnViewerAppearanceChanged));

    public static readonly DependencyProperty ViewerFontSizeProperty =
        DependencyProperty.Register(nameof(ViewerFontSize), typeof(double), typeof(JsonViewer), new PropertyMetadata(14d, OnViewerAppearanceChanged));

    private static readonly Brush KeyBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2563EB"));
    private static readonly Brush StringBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#15803D"));
    private static readonly Brush NumberBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7C3AED"));
    private static readonly Brush BoolBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#B45309"));
    private static readonly Brush NullBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6B7280"));
    private static readonly Brush PunctuationBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#374151"));
    private static readonly Brush DefaultBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#111827"));
    private static readonly Brush ExpirationBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1D4ED8"));

    static JsonViewer()
    {
        KeyBrush.Freeze();
        StringBrush.Freeze();
        NumberBrush.Freeze();
        BoolBrush.Freeze();
        NullBrush.Freeze();
        PunctuationBrush.Freeze();
        DefaultBrush.Freeze();
        ExpirationBrush.Freeze();
    }

    public JsonViewer()
    {
        InitializeComponent();
        Loaded += (_, _) => Render();
        SizeChanged += (_, _) => UpdateDocumentLayout();
    }

    public string JsonText
    {
        get => (string)GetValue(JsonTextProperty);
        set => SetValue(JsonTextProperty, value);
    }

    public ExpirationToolTipInfo? ExpirationInfo
    {
        get => (ExpirationToolTipInfo?)GetValue(ExpirationInfoProperty);
        set => SetValue(ExpirationInfoProperty, value);
    }

    public FontFamily ViewerFontFamily
    {
        get => (FontFamily)GetValue(ViewerFontFamilyProperty);
        set => SetValue(ViewerFontFamilyProperty, value);
    }

    public double ViewerFontSize
    {
        get => (double)GetValue(ViewerFontSizeProperty);
        set => SetValue(ViewerFontSizeProperty, value);
    }

    private static void OnJsonTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        ((JsonViewer)d).Render();
    }

    private static void OnViewerAppearanceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        ((JsonViewer)d).UpdateViewerAppearance();
    }

    private void Render()
    {
        if (!IsLoaded)
        {
            return;
        }

        UpdateViewerAppearance();
        UpdateDocumentLayout();
        Viewer.Document.Blocks.Clear();
        var paragraph = new Paragraph { Margin = new Thickness(0) };
        Viewer.Document.Blocks.Add(paragraph);

        if (string.IsNullOrWhiteSpace(JsonText))
        {
            paragraph.Inlines.Add(new Run(string.Empty));
            return;
        }

        var trimmed = JsonText.Trim();

        try
        {
            using var document = JsonDocument.Parse(trimmed);
            WriteElement(paragraph.Inlines, document.RootElement, 0);
        }
        catch (JsonException)
        {
            paragraph.Inlines.Add(new Run(trimmed) { Foreground = DefaultBrush });
        }
    }

    private void UpdateDocumentLayout()
    {
        Viewer.Document.PagePadding = new Thickness(8);
        Viewer.Document.LineHeight = 22;
        Viewer.Document.PageWidth = Math.Max(0, ActualWidth - 32);
    }

    private void UpdateViewerAppearance()
    {
        Viewer.FontFamily = ViewerFontFamily;
        Viewer.FontSize = ViewerFontSize;
    }

    private void WriteElement(InlineCollection inlines, JsonElement element, int indent)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                WriteObject(inlines, element, indent);
                break;
            case JsonValueKind.Array:
                WriteArray(inlines, element, indent);
                break;
            case JsonValueKind.String:
                inlines.Add(new Run($"\"{element.GetString()}\"") { Foreground = StringBrush });
                break;
            case JsonValueKind.Number:
                inlines.Add(new Run(element.ToString()) { Foreground = NumberBrush });
                break;
            case JsonValueKind.True:
            case JsonValueKind.False:
                inlines.Add(new Run(element.ToString().ToLowerInvariant()) { Foreground = BoolBrush });
                break;
            case JsonValueKind.Null:
                inlines.Add(new Run("null") { Foreground = NullBrush });
                break;
            default:
                inlines.Add(new Run(element.ToString()) { Foreground = DefaultBrush });
                break;
        }
    }

    private void WriteObject(InlineCollection inlines, JsonElement element, int indent)
    {
        inlines.Add(new Run("{") { Foreground = PunctuationBrush });
        var properties = element.EnumerateObject().ToList();
        if (properties.Count > 0)
        {
            inlines.Add(new LineBreak());
        }

        for (var i = 0; i < properties.Count; i++)
        {
            AddIndent(inlines, indent + 1);
            var property = properties[i];
            if (property.Name.Equals("exp", StringComparison.OrdinalIgnoreCase) && ExpirationInfo is not null)
            {
                inlines.Add(new InlineUIContainer(CreateExpirationInline(property)));
            }
            else
            {
                inlines.Add(new Run($"\"{property.Name}\"") { Foreground = KeyBrush });
                inlines.Add(new Run(": ") { Foreground = PunctuationBrush });
                WriteElement(inlines, property.Value, indent + 1);
            }

            if (i < properties.Count - 1)
            {
                inlines.Add(new Run(",") { Foreground = PunctuationBrush });
            }

            inlines.Add(new LineBreak());
        }

        if (properties.Count > 0)
        {
            AddIndent(inlines, indent);
        }

        inlines.Add(new Run("}") { Foreground = PunctuationBrush });
    }

    private void WriteArray(InlineCollection inlines, JsonElement element, int indent)
    {
        inlines.Add(new Run("[") { Foreground = PunctuationBrush });
        var items = element.EnumerateArray().ToList();
        if (items.Count > 0)
        {
            inlines.Add(new LineBreak());
        }

        for (var i = 0; i < items.Count; i++)
        {
            AddIndent(inlines, indent + 1);
            WriteElement(inlines, items[i], indent + 1);
            if (i < items.Count - 1)
            {
                inlines.Add(new Run(",") { Foreground = PunctuationBrush });
            }

            inlines.Add(new LineBreak());
        }

        if (items.Count > 0)
        {
            AddIndent(inlines, indent);
        }

        inlines.Add(new Run("]") { Foreground = PunctuationBrush });
    }

    private static void AddIndent(InlineCollection inlines, int indent)
    {
        inlines.Add(new Run(new string(' ', indent * 2)) { Foreground = DefaultBrush });
    }

    private ToolTip CreateExpirationToolTip()
    {
        var toolTip = new ToolTip
        {
            Content = ExpirationInfo
        };
        toolTip.SetResourceReference(StyleProperty, "GuidanceToolTip");
        toolTip.SetResourceReference(ContentTemplateProperty, "ExpirationToolTipContentTemplate");
        return toolTip;
    }

    private TextBlock CreateExpirationInline(JsonProperty property)
    {
        return new TextBlock
        {
            FontFamily = Viewer.FontFamily,
            FontSize = Viewer.FontSize,
            Foreground = ExpirationBrush,
            Cursor = System.Windows.Input.Cursors.Hand,
            TextDecorations = TextDecorations.Underline,
            Text = $"\"{property.Name}\": {GetCompactJsonValue(property.Value)}",
            ToolTip = CreateExpirationToolTip()
        };
    }

    private static string GetCompactJsonValue(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => $"\"{element.GetString()}\"",
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "null",
            _ => element.ToString()
        };
    }
}
