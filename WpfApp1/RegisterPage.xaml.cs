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

namespace WpfApp1
{
    /// <summary>
    /// RegisterPage.xaml 的交互逻辑
    /// </summary>
    public partial class RegisterPage : Page
    {
        public RegisterPage()
        {
            InitializeComponent();
        }
        private void btnBack_Click(object sender, RoutedEventArgs e)
        {
            NavigationService.GoBack();
        }

        private void btnTemp_Click(object sender, RoutedEventArgs e)
        {
            string input_new_username = new_username.Text;
            string input_new_password = new_password.Text;

            // 使用正则表达式检查
            bool isUsernameValid = Regex.IsMatch(input_new_username, @"^[a-zA-Z0-9]+$");
            string passwordPattern = @"^[a-zA-Z0-9!@#$%^&*()_+=\-]+$";
            bool isPasswordValid = Regex.IsMatch(input_new_password, passwordPattern);

            if (input_new_username.Length < 3 || input_new_username.Length > 20)
            {
                MessageBox.Show("用户名要在3~20个字符长度之间");
                return;
            }
            else if (input_new_password.Length < 3 || input_new_password.Length > 20)
            {
                MessageBox.Show("密码要在3~20个字符长度之间");
                return;
            }

            if (!isUsernameValid)
            {
                MessageBox.Show("用户名只允许大小写字母或数字!");
                return;
            }
            else if (!isPasswordValid)
            {
                MessageBox.Show("密码允许以下内容：\n大小写字母或数字\n! @ # $ % ^ & * ( ) - _ = +");
                return;
            }
            else
            {
                MessageBox.Show("服务器判断用户名是否重复");
            }
        }
    }
}
