using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System;
using System.IO;
using Newtonsoft.Json;

namespace WpfApp1
{
    /// <summary>
    /// RegisterPage.xaml 的交互逻辑
    /// </summary>
    public partial class RegisterPage : Page
    {
        private const string ConfigFilePath = "config.json";
        private readonly Config _config;
        public RegisterPage()
        {
            InitializeComponent();

            // 读取配置文件
            if (!File.Exists(ConfigFilePath))
            {
                // 如果配置文件不存在，创建默认配置文件
                _config = new Config
                {
                    ServerIP = "127.0.0.1",
                    ServerPort = "1080",
                    LocalPort = "3080",
                    Username = "NoName"
                };
                SaveConfig(_config);
            }
            else
            {
                // 从配置文件读取配置
                _config = LoadConfig();
            }

            // 显示配置内容
            ip_addr.Text = _config.ServerIP;
            port.Text = _config.ServerPort;
            local_port.Text = _config.LocalPort;
        }
        private void btnBack_Click(object sender, RoutedEventArgs e)
        {
            NavigationService.GoBack();
        }

        private void btnTemp_Click(object sender, RoutedEventArgs e)
        {
            // 验证输入是否合法
            if (IsValidIP(ip_addr.Text) && IsValidPort(port.Text) && IsValidPort(local_port.Text))
            {
                // 更新配置并保存
                _config.ServerIP = ip_addr.Text;
                _config.ServerPort = port.Text;
                _config.LocalPort = local_port.Text;
                SaveConfig(_config);
            }
            else
            {
                // 弹出非法输入提示
                MessageBox.Show("输入非法", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private bool IsValidIP(string ip)
        {
            return Regex.IsMatch(ip, @"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." +
                                      @"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." +
                                      @"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." +
                                      @"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
        }

        private bool IsValidPort(string port)
        {
            return Regex.IsMatch(port, @"^([0-9]{1,5})$") && int.Parse(port) <= 65535;
        }

        private Config LoadConfig()
        {
            var json = File.ReadAllText(ConfigFilePath);
            return JsonConvert.DeserializeObject<Config>(json);
        }

        private void SaveConfig(Config config)
        {
            var json = JsonConvert.SerializeObject(config, Formatting.Indented);
            File.WriteAllText(ConfigFilePath, json);
            MessageBox.Show("保存成功");
        }

    }
}
