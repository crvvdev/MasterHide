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
    public partial class InstallDriverForm : Form
    {
        private string _driverPath { get; set; }
        private HookType _hookType { get; set; }

        public InstallDriverForm()
        {
            InitializeComponent();
        }

        public string GetDriverPath()
        {
            return _driverPath;
        }

        public HookType GetHookType()
        {
            return _hookType;
        }

        private void comboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            _hookType = (HookType)comboBoxHookTypes.SelectedIndex + 1;
        }

        private void btnOK_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }

        private void btnBrowse_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Title = "Select MasterHide driver location";
                openFileDialog.Filter = "Driver files (*.sys)|*.sys";
                openFileDialog.FilterIndex = 1;
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    textBoxDriverPath.Text = openFileDialog.FileName;
                    _driverPath = openFileDialog.FileName;
                }
            }
        }
    }
}
