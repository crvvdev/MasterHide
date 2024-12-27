using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MasterHideGUI
{
    public partial class MainForm : Form
    {
        private List<ProcessRule> _rules { get; set; }
        private DriverManager _driverManager { get; set; }

        public MainForm()
        {
            InitializeComponent();
            _rules = RulesManager.LoadRules();
            _driverManager = new DriverManager();

            foreach (var processRule in _rules)
            {
                ListViewItem item = new ListViewItem(processRule.ImageFileName);
                item.Tag = processRule;
                listViewItems.Items.Add(item);
            }

            RefreshServiceStatus();
        }

        private void RefreshServiceStatus()
        {
            ServiceController sc = _driverManager.GetServiceController();
            if (sc != null)
            {
                installDriverToolStripMenuItem.Enabled = false;
                reinstallDriverToolStripMenuItem.Enabled = true;

                if (sc.Status == ServiceControllerStatus.Running)
                {
                    startDriverToolStripMenuItem.Enabled = false;
                    stopDriverToolStripMenuItem.Enabled = true;
                    restartDriverToolStripMenuItem.Enabled = true;
                }
                else if (sc.Status == ServiceControllerStatus.Stopped)
                {
                    startDriverToolStripMenuItem.Enabled = true;
                    stopDriverToolStripMenuItem.Enabled = false;
                    restartDriverToolStripMenuItem.Enabled = false;
                }
            }
            else
            {
                installDriverToolStripMenuItem.Enabled = true;
                reinstallDriverToolStripMenuItem.Enabled = false;
            }
        }

        private void btnAddItem_Click(object sender, EventArgs e)
        {
        Retry:
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Title = "Select file to attach process rules";
                openFileDialog.Filter = "All files (*.*)|*.*";
                openFileDialog.FilterIndex = 1;
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string filePath = openFileDialog.FileName;
                    bool exists = false;

                    foreach (ListViewItem item in listViewItems.Items)
                    {
                        if (item.Text == filePath)
                        {
                            exists = true;
                            break;
                        }
                    }

                    if (!exists)
                    {
                        var processRule = new ProcessRule("Default", filePath);
                        var editForm = new EditForm(processRule);

                        if (editForm.ShowDialog() == DialogResult.OK)
                        {
                            ListViewItem item = new ListViewItem(filePath);
                            item.Tag = processRule;
                            listViewItems.Items.Add(item);

                            _rules.Add(processRule);
                            RulesManager.SaveRules(_rules);
                        }
                    }
                    else
                    {
                        MessageBox.Show("The file is already in the list.", "Duplicated process rules", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        goto Retry;
                    }
                    //}
                }
            }
        }

        private void ListViewItems_SelectedIndexChanged(object sender, EventArgs e)
        {
            bool isItemSelected = listViewItems.SelectedItems.Count > 0;
            btnEditItem.Enabled = isItemSelected;
            btnRemoveItem.Enabled = isItemSelected;
            btnApply.Enabled = isItemSelected;
        }

        private void btnEditItem_Click(object sender, EventArgs e)
        {
            if (listViewItems.SelectedItems.Count > 0)
            {
                ListViewItem selectedItem = listViewItems.SelectedItems[0];
                var processRuleEntry = (ProcessRule)selectedItem.Tag;

                var editForm = new EditForm(processRuleEntry);
                if (editForm.ShowDialog() == DialogResult.OK)
                {
                    selectedItem.Tag = processRuleEntry;

                    // Update rules and save
                    //
                    int idx = _rules.FindIndex(p => p.ImageFileName == processRuleEntry.ImageFileName);
                    if (idx >= 0)
                    {
                        RulesManager.SaveRules(_rules);
                    }
                }
            }
        }

        private void btnRemoveItem_Click(object sender, EventArgs e)
        {
            if (listViewItems.SelectedItems.Count > 0)
            {
                var selectedItem = listViewItems.SelectedItems[0];
                var processRule = (ProcessRule)selectedItem.Tag;

                _rules.Remove(processRule);
                RulesManager.SaveRules(_rules);

                listViewItems.Items.Remove(selectedItem);
                ListViewItems_SelectedIndexChanged(sender, e);

                _driverManager.RemoveProcessRule(processRule.ImageFileName);
                MessageBox.Show($"Successfully removed process rule for entry {processRule.ImageFileName}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var aboutBox = new AboutBox();
            aboutBox.ShowDialog();
        }

        private void checkDriverToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                _driverManager.GetDeviceHandle();
                MessageBox.Show($"MasterHide driver is running!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open handle to MasterHide driver! {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void installDriverToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                var installDriverForm = new InstallDriverForm();
                if (installDriverForm.ShowDialog() == DialogResult.OK)
                {
                    _driverManager.InstallService(installDriverForm.GetDriverPath(), installDriverForm.GetHookType());
                    MessageBox.Show("Successfully installed service", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    RefreshServiceStatus();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to install driver: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void reinstallDriverToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                var installDriverForm = new InstallDriverForm();
                if (installDriverForm.ShowDialog() == DialogResult.OK)
                {
                    _driverManager.ReinstallService(installDriverForm.GetDriverPath(), installDriverForm.GetHookType());
                    MessageBox.Show("Successfully re-installed service", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    RefreshServiceStatus();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to re-install driver: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void helpToolStripMenuItem_Click(object sender, EventArgs e)
        {
            RefreshServiceStatus();
        }

        private void startDriverToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                _driverManager.StartService();
                MessageBox.Show("Successfully started service!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                RefreshServiceStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to start service: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void stopDriverToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                _driverManager.StopService();
                MessageBox.Show("Successfully stopped service!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                RefreshServiceStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to stop service: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void restartDriverToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                _driverManager.StopService();
                _driverManager.StartService();
                MessageBox.Show("Successfully restarted service!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                RefreshServiceStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to restart service: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnApply_Click(object sender, EventArgs e)
        {
            try
            {
                if (listViewItems.SelectedItems.Count > 0)
                {
                    ListViewItem selectedItem = listViewItems.SelectedItems[0];
                    var processRule = (ProcessRule)selectedItem.Tag;
                    var profiles = ProfileManager.LoadProfiles();

                    int idx = profiles.FindIndex(p => p.ProfileName == processRule.ProfileName);
                    if (idx >= 0)
                    {
                        _driverManager.SendProcessRule(processRule.ImageFileName, profiles[idx].PolicyFlags);
                        MessageBox.Show($"Successfully created/updated rules!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to create rule: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void MainForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            RulesManager.SaveRules(_rules);
        }
    }
}
