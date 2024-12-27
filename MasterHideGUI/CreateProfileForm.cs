using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MasterHideGUI
{
    public partial class CreateProfileForm : Form
    {
        private string _profileName = string.Empty;

        public CreateProfileForm()
        {
            InitializeComponent();
        }

        public string GetProfileName()
        {
            return _profileName;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            _profileName = textBoxProfileName.Text;

            if(string.IsNullOrWhiteSpace(_profileName))
            {
                MessageBox.Show("Invalid name for profile!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            this.DialogResult = DialogResult.OK;
            this.Close();
        }
    }
}
