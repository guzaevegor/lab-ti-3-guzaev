using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace WpfApp1
{
    public partial class MainWindow : Window
    {
        // Замена переменных в классе
        private int p, q, n, phi, kc, ko;
        private List<int> encryptedValues = new List<int>();
        private List<byte> decryptedValues = new List<byte>();
        // Буферы для хранения данных
        private byte[] sourceBytes;
        private byte[] encryptedBytes;

        public MainWindow()
        {
            InitializeComponent();
        }

        #region Параметры RSA и валидация

        private void PTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (int.TryParse(PTextBox.Text, out int value))
            {
                if (IsPrime(value))
                {
                    p = value;
                    PValidationLabel.Content = "P является простым числом";
                    UpdateCalculatedParameters();
                }
                else
                {
                    PValidationLabel.Content = "P должно быть простым числом";
                }
            }
            else
            {
                PValidationLabel.Content = "Введите целое число P";
            }
        }


        private void QTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (int.TryParse(QTextBox.Text, out int value))
            {
                if (IsPrime(value))
                {
                    q = value;
                    QValidationLabel.Content = "Q является простым числом";
                    UpdateCalculatedParameters();
                }
                else
                {
                    QValidationLabel.Content = "Q должно быть простым числом";
                }
            }
            else
            {
                QValidationLabel.Content = "Введите целое число Q";
            }
        }


        private void KCTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (phi == 0)
            {
                KCValidationLabel.Content = "Сначала введите P и Q";
                return;
            }

            if (int.TryParse(KCTextBox.Text, out int value))
            {
                // KC должен быть взаимно простым с phi и меньше phi
                if (value > 1 && value < phi && FindGcd(value, phi) == 1)
                {
                    kc = value;
                    // Вычисляем открытый ключ KO используя расширенный алгоритм Евклида
                    var extendedEuclidResult = ExtendedEuclidean(phi, kc);
                    ko = extendedEuclidResult.y;

                    KCValidationLabel.Content = "KC является допустимым значением";
                    KOValueTextBlock.Text = ko.ToString();

                    AddToLog($"Введен закрытый ключ KC = {kc}");
                    AddToLog($"Вычислен открытый ключ KO = {ko}");
                    StatusTextBlock.Text = "Готово к шифрованию/дешифрованию";
                }
                else
                {
                    KCValidationLabel.Content = "KC должно быть взаимно простым с φ(N) и меньше φ(N)";
                }
            }
            else
            {
                KCValidationLabel.Content = "Введите целое число KC";
            }
        }
        private void UpdateCalculatedParameters()
        {
            if (p > 0 && q > 0)
            {
                // Проверка на подходящий размер модуля для 8->16 бит
                if ((long)p * q > ushort.MaxValue)
                {
                    AddToLog("Внимание: произведение P*Q > 65535. Зашифрованное значение может не влезть в 2 байта.");
                }

                try
                {
                    n = p * q;
                    phi = (p - 1) * (q - 1);

                    NValueTextBlock.Text = n.ToString();
                    PhiValueTextBlock.Text = phi.ToString();

                    AddToLog($"Вычислен модуль N = P * Q = {p} * {q} = {n}");
                    AddToLog($"Вычислена функция Эйлера φ(N) = (P-1) * (Q-1) = {p - 1} * {q - 1} = {phi}");

                    // Сбрасываем ключи при изменении параметров
                    KCTextBox.Clear();
                    KOValueTextBlock.Text = "—";
                }
                catch (OverflowException)
                {
                    MessageBox.Show("Произведение P и Q слишком большое для типа int. Используйте меньшие числа.",
                                  "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                    p = q = 0;
                    NValueTextBlock.Text = "—";
                    PhiValueTextBlock.Text = "—";
                }
            }
        }
        #endregion

        #region Алгоритмы RSA

        private bool IsPrime(int number)
        {
            if (number <= 1) return false;
            if (number <= 3) return true;
            if (number % 2 == 0 || number % 3 == 0) return false;

            for (int i = 5; i * i <= number; i += 6)
            {
                if (number % i == 0 || number % (i + 2) == 0)
                    return false;
            }

            return true;
        }

        private int FindGcd(int a, int b) => b == 0 ? a : FindGcd(b, a % b);

        private int QuickPowerMod(int num, int power, int mod)
        {
            if (mod == 1) return 0;
            if (power == 0) return 1;
            if (num == 0) return 0;

            int result = 1;
            int current = num % mod;
            int exponent = power;

            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                    result = (int)(((long)result * current) % mod);

                current = (int)(((long)current * current) % mod);
                exponent /= 2;
            }

            return result;
        }

        private (int gcd, int x, int y) ExtendedEuclidean(int a, int b)
        {
            int x0 = 1, y0 = 0, x1 = 0, y1 = 1;
            int d0 = a, d1 = b;

            while (d1 != 0)
            {
                int q = d0 / d1;
                int d2 = d0 % d1;
                int x2 = x0 - q * x1;
                int y2 = y0 - q * y1;

                d0 = d1;
                d1 = d2;
                x0 = x1;
                x1 = x2;
                y0 = y1;
                y1 = y2;
            }

            if (y0 < 0)
                y0 += a;

            return (d0, x0, y0);
        }

        #endregion

        #region Шифрование и дешифрование

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            // Проверяем, что все параметры заданы
            if (n == 0 || phi == 0 || ko == 0)
            {
                MessageBox.Show("Пожалуйста, введите корректные параметры P, Q и KC", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // Проверяем, что есть исходные данные
            if (sourceBytes == null || sourceBytes.Length == 0)
            {
                MessageBox.Show("Нет исходных данных для шифрования. Сначала откройте файл с текстом.",
                              "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                StatusTextBlock.Text = "Выполняется шифрование...";
                ResultsHeaderLabel.Content = "Зашифрованные значения (десятичная система):";

                // Очищаем предыдущие результаты
                ResultsTextBox.Clear();
                encryptedValues.Clear();

                AddToLog("Начинаем шифрование...");

                StringBuilder resultText = new StringBuilder();
                List<byte> encryptedBytesList = new List<byte>();

                // Настраиваем прогресс-бар
                OperationProgressBar.Maximum = sourceBytes.Length;
                OperationProgressBar.Value = 0;

                // Шифруем каждый байт
                for (int i = 0; i < sourceBytes.Length; i++)
                {
                    byte b = sourceBytes[i];
                    int m = b;

                    // C = M^e mod n (шифрование с открытым ключом e=ko)
                    int encrypted = QuickPowerMod(m, ko, n);
                    encryptedValues.Add(encrypted);

                    // Добавляем в результат
                    resultText.AppendLine($"{b} -> {encrypted}");

                    // Преобразуем в 2 байта (ushort)
                    byte[] encBytes = BitConverter.GetBytes((ushort)encrypted);
                    encryptedBytesList.Add(encBytes[0]);
                    encryptedBytesList.Add(encBytes[1]);

                    // Обновляем прогресс-бар
                    OperationProgressBar.Value = i + 1;
                }

                // Сохраняем зашифрованные байты
                encryptedBytes = encryptedBytesList.ToArray();

                // Отображаем результаты
                ResultsTextBox.Text = resultText.ToString();

                // Обновляем информацию
                DataInfoTextBlock.Text = $"Исходных байт: {sourceBytes.Length} | Результат: {encryptedBytes.Length} байт";

                AddToLog($"Шифрование завершено. Получено {encryptedValues.Count} зашифрованных значений.");
                StatusTextBlock.Text = "Шифрование завершено успешно";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при шифровании: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "Ошибка при шифровании";
            }
            finally
            {
                OperationProgressBar.Value = 0;
            }
        }



        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            // Проверяем, что все параметры заданы
            if (n == 0 || kc == 0)
            {
                MessageBox.Show("Пожалуйста, введите корректные параметры P, Q и KC", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // Проверяем, что есть зашифрованные данные
            if (encryptedBytes == null || encryptedBytes.Length == 0)
            {
                MessageBox.Show("Нет зашифрованных данных для расшифровки. Сначала откройте зашифрованный файл.",
                              "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                StatusTextBlock.Text = "Выполняется расшифровка...";
                ResultsHeaderLabel.Content = "Расшифрованные значения (десятичная система):";

                // Очищаем предыдущие результаты
                ResultsTextBox.Clear();
                decryptedValues.Clear();

                AddToLog("Начинаем расшифровку...");

                StringBuilder resultText = new StringBuilder();
                List<byte> decryptedBytesList = new List<byte>();

                // Настраиваем прогресс-бар
                OperationProgressBar.Maximum = encryptedBytes.Length / 2;
                OperationProgressBar.Value = 0;

                // Расшифровываем каждый 2-байтовый блок
                for (int i = 0; i < encryptedBytes.Length; i += 2)
                {
                    // Преобразуем 2 байта в число
                    ushort encryptedValue = BitConverter.ToUInt16(encryptedBytes, i);

                    // M = C^d mod n (расшифровка с закрытым ключом d=kc)
                    int decrypted = QuickPowerMod(encryptedValue, kc, n);

                    // Убедимся, что результат - байт (0-255)
                    if (decrypted >= 0 && decrypted <= 255)
                    {
                        byte decryptedByte = (byte)decrypted;
                        decryptedBytesList.Add(decryptedByte);

                        // Добавляем в результат
                        resultText.AppendLine($"{encryptedValue} -> {decrypted}");
                    }
                    else
                    {
                        AddToLog($"Внимание: расшифрованное значение {decrypted} выходит за пределы байта (0-255)");
                        decryptedBytesList.Add(0); // Добавляем нулевой байт в случае ошибки
                        resultText.AppendLine($"{encryptedValue} -> {decrypted} (!!!)");
                    }

                    // Обновляем прогресс-бар
                    OperationProgressBar.Value = (i / 2) + 1;
                }

                // Сохраняем расшифрованные байты
                decryptedValues = decryptedBytesList;

                // Отображаем результаты
                ResultsTextBox.Text = resultText.ToString();

                // Обновляем информацию
                DataInfoTextBlock.Text = $"Зашифрованных байт: {encryptedBytes.Length} | Результат: {decryptedBytesList.Count} байт";

                AddToLog($"Расшифровка завершена. Получено {decryptedBytesList.Count} расшифрованных байт.");
                StatusTextBlock.Text = "Расшифровка завершена успешно";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при расшифровке: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = "Ошибка при расшифровке";
            }
            finally
            {
                OperationProgressBar.Value = 0;
            }
        }


        #endregion

        #region Вспомогательные методы

        private void AddToLog(string message)
        {
            LogItemsControl.Items.Add($"[{DateTime.Now.ToString("HH:mm:ss")}] {message}");
        }

        private void OpenMenuItem_Click(object sender, RoutedEventArgs e)
        {
            // Определяем, какой режим работы сейчас выбран
            bool isEncryptMode = true; // По умолчанию режим шифрования

            // Если вызвано из кнопки "Открыть файл с зашифрованным текстом", меняем режим
            if (sender is Button button && button.Content.ToString().Contains("зашифрованным"))
            {
                isEncryptMode = false;
            }

            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = isEncryptMode ?
                    "Все файлы (*.*)|*.*" :
                    "Все файлы (*.*)|*.*",
                Title = isEncryptMode ?
                    "Выберите файл для шифрования" :
                    "Выберите файл для расшифровки"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    if (isEncryptMode)
                    {
                        // Читаем исходный файл для шифрования
                        sourceBytes = File.ReadAllBytes(openFileDialog.FileName);

                        // Отображаем исходные данные как числа
                        StringBuilder sourceDisplay = new StringBuilder();
                        for (int i = 0; i < sourceBytes.Length; i++)
                        {
                            sourceDisplay.Append(sourceBytes[i] + " ");
                            if ((i + 1) % 16 == 0) sourceDisplay.AppendLine();
                        }

                        SourceTextBox.Text = sourceDisplay.ToString();
                        DataInfoTextBlock.Text = $"Исходных байт: {sourceBytes.Length}";

                        AddToLog($"Открыт файл для шифрования: {openFileDialog.FileName}");
                        AddToLog($"Размер файла: {sourceBytes.Length} байт");
                        StatusTextBlock.Text = "Файл готов к шифрованию";
                    }
                    else
                    {
                        // Читаем зашифрованный файл для расшифровки
                        encryptedBytes = File.ReadAllBytes(openFileDialog.FileName);

                        // Проверяем, что размер кратен 2 байтам
                        if (encryptedBytes.Length % 2 != 0)
                        {
                            throw new Exception("Неверный формат зашифрованного файла. Размер должен быть кратен 2 байтам.");
                        }

                        // Отображаем зашифрованные данные как числа
                        StringBuilder encryptedDisplay = new StringBuilder();
                        for (int i = 0; i < encryptedBytes.Length; i += 2)
                        {
                            ushort value = BitConverter.ToUInt16(encryptedBytes, i);
                            encryptedDisplay.Append(value + " ");
                            if ((i + 2) % 16 == 0) encryptedDisplay.AppendLine();
                        }

                        SourceTextBox.Text = encryptedDisplay.ToString();
                        DataInfoTextBlock.Text = $"Зашифрованных байт: {encryptedBytes.Length} (значений: {encryptedBytes.Length / 2})";

                        AddToLog($"Открыт зашифрованный файл: {openFileDialog.FileName}");
                        AddToLog($"Размер файла: {encryptedBytes.Length} байт");
                        StatusTextBlock.Text = "Файл готов к расшифровке";
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Ошибка при открытии файла: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }


        private void SaveMenuItem_Click(object sender, RoutedEventArgs e)
        {
            // Определяем, какой режим работы и какие данные сохранять
            bool isSavingEncrypted = false;

            // Если вызвано из кнопки "Сохранить зашифрованный текст", меняем режим
            if (sender is Button button && button.Content.ToString().Contains("зашифрованный"))
            {
                isSavingEncrypted = true;
            }
            else if (encryptedBytes != null && encryptedBytes.Length > 0 &&
                     (decryptedValues == null || decryptedValues.Count == 0))
            {
                // Если есть только зашифрованные данные
                isSavingEncrypted = true;
            }

            if (isSavingEncrypted && (encryptedBytes == null || encryptedBytes.Length == 0))
            {
                MessageBox.Show("Нет зашифрованных данных для сохранения. Сначала выполните шифрование.",
                              "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (!isSavingEncrypted && (decryptedValues == null || decryptedValues.Count == 0))
            {
                MessageBox.Show("Нет расшифрованных данных для сохранения. Сначала выполните расшифровку.",
                              "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            SaveFileDialog saveFileDialog = new SaveFileDialog
            {
                Filter = "Все файлы (*.*)|*.*",
                Title = isSavingEncrypted ?
                    "Сохранить зашифрованный файл" :
                    "Сохранить расшифрованный файл"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    if (isSavingEncrypted)
                    {
                        File.WriteAllBytes(saveFileDialog.FileName, encryptedBytes);
                        AddToLog($"Зашифрованный файл сохранен: {saveFileDialog.FileName}");
                        StatusTextBlock.Text = "Зашифрованный файл сохранен";
                    }
                    else
                    {
                        File.WriteAllBytes(saveFileDialog.FileName, decryptedValues.ToArray());
                        AddToLog($"Расшифрованный файл сохранен: {saveFileDialog.FileName}");
                        StatusTextBlock.Text = "Расшифрованный файл сохранен";
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Ошибка при сохранении файла: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void AboutMenuItem_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("RSA Шифрование\n\nПрограмма для шифрования и расшифрования файлов с использованием алгоритма RSA.",
                "О программе", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void DocumentationMenuItem_Click(object sender, RoutedEventArgs e)
        {
            StringBuilder help = new StringBuilder();
            help.AppendLine("Инструкция по использованию:");
            help.AppendLine("1. Введите простые числа P и Q");
            help.AppendLine("2. Введите закрытый ключ KC (должен быть взаимно простым с φ(N))");
            help.AppendLine("3. Система автоматически вычислит открытый ключ KO");
            help.AppendLine("4. Нажмите 'Шифровать' для зашифровки файла или 'Расшифровать' для расшифровки");
            help.AppendLine("5. Выберите файл для операции");
            help.AppendLine("6. Сохраните результат операции");
            help.AppendLine("\nАлгоритм RSA:");
            help.AppendLine("- Шифрование: C = M^KO mod N");
            help.AppendLine("- Расшифрование: M = C^KC mod N");
            help.AppendLine("\nВыбор параметров:");
            help.AppendLine("- P и Q должны быть простыми числами");
            help.AppendLine("- Для корректной работы убедитесь, что P*Q < 65536 (2 байта)");
            help.AppendLine("- KC должен быть взаимно простым с φ(N)=(P-1)*(Q-1)");

            MessageBox.Show(help.ToString(), "Документация", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        #endregion
    }
}
