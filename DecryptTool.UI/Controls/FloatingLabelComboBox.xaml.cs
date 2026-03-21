using System.Collections;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DecryptTool.UI.Controls;

public partial class FloatingLabelComboBox : UserControl
{
    public static readonly DependencyProperty LabelProperty =
        DependencyProperty.Register(nameof(Label), typeof(string), typeof(FloatingLabelComboBox), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty ItemsSourceProperty =
        DependencyProperty.Register(nameof(ItemsSource), typeof(IEnumerable), typeof(FloatingLabelComboBox), new PropertyMetadata(null));

    public static readonly DependencyProperty SelectedItemProperty =
        DependencyProperty.Register(
            nameof(SelectedItem),
            typeof(object),
            typeof(FloatingLabelComboBox),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnSelectedItemChanged));

    public FloatingLabelComboBox()
    {
        InitializeComponent();
        Loaded += (_, _) => UpdateVisualState();
    }

    public string Label
    {
        get => (string)GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    public IEnumerable? ItemsSource
    {
        get => (IEnumerable?)GetValue(ItemsSourceProperty);
        set => SetValue(ItemsSourceProperty, value);
    }

    public object? SelectedItem
    {
        get => GetValue(SelectedItemProperty);
        set => SetValue(SelectedItemProperty, value);
    }

    private static void OnSelectedItemChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        ((FloatingLabelComboBox)d).UpdateVisualState();
    }

    private void InputBox_OnGotFocus(object sender, RoutedEventArgs e) => UpdateVisualState();

    private void InputBox_OnLostFocus(object sender, RoutedEventArgs e) => UpdateVisualState();

    private void InputBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateVisualState();

    private void UpdateVisualState()
    {
        if (!IsLoaded)
        {
            return;
        }

        var shouldFloat = InputBox.IsKeyboardFocusWithin || SelectedItem is not null;
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
