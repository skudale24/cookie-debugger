using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DecryptTool.UI.Controls;

public partial class FloatingLabelTextBox : UserControl
{
    public static readonly DependencyProperty LabelProperty =
        DependencyProperty.Register(nameof(Label), typeof(string), typeof(FloatingLabelTextBox), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty TextProperty =
        DependencyProperty.Register(
            nameof(Text),
            typeof(string),
            typeof(FloatingLabelTextBox),
            new FrameworkPropertyMetadata(string.Empty, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnTextChanged));

    public static readonly DependencyProperty AcceptsReturnProperty =
        DependencyProperty.Register(nameof(AcceptsReturn), typeof(bool), typeof(FloatingLabelTextBox), new PropertyMetadata(false));

    public static readonly DependencyProperty TextWrappingProperty =
        DependencyProperty.Register(nameof(TextWrapping), typeof(TextWrapping), typeof(FloatingLabelTextBox), new PropertyMetadata(TextWrapping.NoWrap));

    public static readonly DependencyProperty IsReadOnlyProperty =
        DependencyProperty.Register(nameof(IsReadOnly), typeof(bool), typeof(FloatingLabelTextBox), new PropertyMetadata(false));

    public static readonly DependencyProperty InputFontFamilyProperty =
        DependencyProperty.Register(nameof(InputFontFamily), typeof(FontFamily), typeof(FloatingLabelTextBox), new PropertyMetadata(new FontFamily("Segoe UI")));

    public static readonly DependencyProperty InputFontSizeProperty =
        DependencyProperty.Register(nameof(InputFontSize), typeof(double), typeof(FloatingLabelTextBox), new PropertyMetadata(14d));

    public static readonly DependencyProperty MinTextBoxHeightProperty =
        DependencyProperty.Register(nameof(MinTextBoxHeight), typeof(double), typeof(FloatingLabelTextBox), new PropertyMetadata(24d));

    public static readonly DependencyProperty VerticalScrollBarVisibilityProperty =
        DependencyProperty.Register(nameof(VerticalScrollBarVisibility), typeof(ScrollBarVisibility), typeof(FloatingLabelTextBox), new PropertyMetadata(ScrollBarVisibility.Disabled));

    public static readonly DependencyProperty HorizontalScrollBarVisibilityProperty =
        DependencyProperty.Register(nameof(HorizontalScrollBarVisibility), typeof(ScrollBarVisibility), typeof(FloatingLabelTextBox), new PropertyMetadata(ScrollBarVisibility.Disabled));

    public FloatingLabelTextBox()
    {
        InitializeComponent();
        Loaded += (_, _) => UpdateVisualState();
    }

    public string Label
    {
        get => (string)GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    public string Text
    {
        get => (string)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    public bool AcceptsReturn
    {
        get => (bool)GetValue(AcceptsReturnProperty);
        set => SetValue(AcceptsReturnProperty, value);
    }

    public TextWrapping TextWrapping
    {
        get => (TextWrapping)GetValue(TextWrappingProperty);
        set => SetValue(TextWrappingProperty, value);
    }

    public bool IsReadOnly
    {
        get => (bool)GetValue(IsReadOnlyProperty);
        set => SetValue(IsReadOnlyProperty, value);
    }

    public FontFamily InputFontFamily
    {
        get => (FontFamily)GetValue(InputFontFamilyProperty);
        set => SetValue(InputFontFamilyProperty, value);
    }

    public double InputFontSize
    {
        get => (double)GetValue(InputFontSizeProperty);
        set => SetValue(InputFontSizeProperty, value);
    }

    public double MinTextBoxHeight
    {
        get => (double)GetValue(MinTextBoxHeightProperty);
        set => SetValue(MinTextBoxHeightProperty, value);
    }

    public ScrollBarVisibility VerticalScrollBarVisibility
    {
        get => (ScrollBarVisibility)GetValue(VerticalScrollBarVisibilityProperty);
        set => SetValue(VerticalScrollBarVisibilityProperty, value);
    }

    public ScrollBarVisibility HorizontalScrollBarVisibility
    {
        get => (ScrollBarVisibility)GetValue(HorizontalScrollBarVisibilityProperty);
        set => SetValue(HorizontalScrollBarVisibilityProperty, value);
    }

    private static void OnTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        ((FloatingLabelTextBox)d).UpdateVisualState();
    }

    private void InputBox_OnGotFocus(object sender, RoutedEventArgs e) => UpdateVisualState();

    private void InputBox_OnLostFocus(object sender, RoutedEventArgs e) => UpdateVisualState();

    private void InputBox_OnTextChanged(object sender, TextChangedEventArgs e) => UpdateVisualState();

    private void UpdateVisualState()
    {
        if (!IsLoaded)
        {
            return;
        }

        var shouldFloat = InputBox.IsKeyboardFocusWithin || !string.IsNullOrWhiteSpace(Text);
        LabelTransform.Y = shouldFloat ? 0 : 24;
        FloatingLabel.FontSize = shouldFloat ? 12 : 14;
        FloatingLabel.Foreground = InputBox.IsKeyboardFocusWithin
            ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2563EB"))
            : new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6B7280"));
        LabelBackground.Background = shouldFloat
            ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFFFFF"))
            : Brushes.Transparent;
        InputBorder.BorderBrush = InputBox.IsKeyboardFocusWithin
            ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2563EB"))
            : new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D1D5DB"));
        InputBorder.BorderThickness = InputBox.IsKeyboardFocusWithin ? new Thickness(2) : new Thickness(1);
    }
}
