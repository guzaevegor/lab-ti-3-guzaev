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
        private BigInteger p, q, n, phi, kc, ko;
        private List<BigInteger> encryptedValues = new List<BigInteger>();
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
            if (BigInteger.TryParse(PTextBox.Text, out BigInteger value))
            {
                if (IsPrimeMillerRabin(value, 5))
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
            if (BigInteger.TryParse(QTextBox.Text, out BigInteger value))
            {
                if (IsPrimeMillerRabin(value, 5))
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

            if (BigInteger.TryParse(KCTextBox.Text, out BigInteger value))
            {
                // KC должен быть взаимно простым с phi и меньше phi
                if (value > 1 && value < phi && BigInteger.GreatestCommonDivisor(value, phi) == 1)
                {
                    kc = value;
                    // Вычисляем открытый ключ KO используя расширенный алгоритм Евклида
                    ko = ModInverse(kc, phi);
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
                if (p * q > 65535)
                {
                    AddToLog("Внимание: произведение P*Q > 65535. Зашифрованное значение может не влезть в 2 байта.");
                }

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
        }

        #endregion

        #region Алгоритмы RSA

        // Тест Миллера-Рабина для проверки на простоту
        private bool IsPrimeMillerRabin(BigInteger n, int k)
        {
            // Простые случаи
            if (n <= 1) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0) return false;

            // Представляем n-1 в виде d * 2^s
            BigInteger d = n - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            // Проводим k тестов
            Random rand = new Random();
            for (int i = 0; i < k; i++)
            {
                BigInteger a = RandomBigInteger(2, n - 2, rand);
                BigInteger x = BigInteger.ModPow(a, d, n);

                if (x == 1 || x == n - 1)
                    continue;

                bool isProbablePrime = false;
                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == 1)
                        return false;
                    if (x == n - 1)
                    {
                        isProbablePrime = true;
                        break;
                    }
                }

                if (!isProbablePrime)
                    return false;
            }

            return true;
        }

        // Генерация случайного BigInteger в диапазоне [min, max]
        private BigInteger RandomBigInteger(BigInteger min, BigInteger max, Random random)
        {
            byte[] bytes = max.ToByteArray();
            random.NextBytes(bytes);
            bytes[bytes.Length - 1] &= 0x7F; // Убедимся, что число положительное

            BigInteger randomNumber = new BigInteger(bytes);
            return min + (randomNumber % (max - min + 1));
        }

        // Расширенный алгоритм Евклида для нахождения мультипликативного обратного
        private BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            AddToLog("Запуск расширенного алгоритма Евклида:");

            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            AddToLog($"Начальные значения: a = {a}, m = {m}, x = {x}, y = {y}");

            if (m == 1)
                return 0;

            while (a > 1)
            {
                // Сохраняем текущие значения для логирования
                BigInteger aOld = a;
                BigInteger mOld = m;
                BigInteger xOld = x;
                BigInteger yOld = y;

                // Находим частное и остаток
                BigInteger q = a / m;
                BigInteger t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;

                AddToLog($"q = {aOld} / {mOld} = {q}, остаток = {m}");
                AddToLog($"x' = {xOld}, y' = {yOld} => x = {t}, y = {xOld} - {q} * {yOld} = {y}");
            }

            if (x < 0)
            {
                x += m0;
                AddToLog($"Отрицательное x, прибавляем модуль: {x - m0} + {m0} = {x}");
            }

            AddToLog($"Результат: мультипликативное обратное = {x}");
            return x;
        }

        // Быстрое возведение в степень по модулю (для наглядности, можно использовать BigInteger.ModPow)
        private BigInteger ModPow(BigInteger baseVal, BigInteger exponent, BigInteger modulus)
        {
            AddToLog($"Быстрое возведение в степень: {baseVal}^{exponent} mod {modulus}");

            if (modulus == 1)
                return 0;

            BigInteger result = 1;
            baseVal = baseVal % modulus;

            while (exponent > 0)
            {
                // Если показатель нечетный
                if (exponent % 2 == 1)
                {
                    result = (result * baseVal) % modulus;
                    AddToLog($"  Показатель нечетный: result = (result * base) % modulus = {result}");
                }

                // Сдвигаем показатель вправо (делим на 2)
                exponent = exponent >> 1;
                // Возводим основание в квадрат
                baseVal = (baseVal * baseVal) % modulus;

                if (exponent > 0)
                    AddToLog($"  Основание в квадрат: base = {baseVal}, показатель = {exponent}");
            }

            AddToLog($"Результат: {result}");
            return result;
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
                    BigInteger m = b;

                    // C = M^e mod n (шифрование с открытым ключом e=ko)
                    BigInteger encrypted = ModPow(m, ko, n);
                    encryptedValues.Add(encrypted);

                    // Добавляем в результат
                    resultText.AppendLine($"{b} -> {encrypted}");

                    // Преобразуем в 2 байта
                    byte[] encBytes = BitConverter.GetBytes((ushort)(encrypted % 65536));
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
                StatusTextBlock.Text = "Шифрование завершено успешно. Выберите 'Файл -> Сохранить результат' для сохранения.";
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
                    BigInteger decrypted = ModPow(encryptedValue, kc, n);

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
                StatusTextBlock.Text = "Расшифровка завершена успешно. Выберите 'Файл -> Сохранить результат' для сохранения.";
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
