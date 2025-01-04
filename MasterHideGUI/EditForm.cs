using System;
using System.Collections.Generic;
using System.Windows.Forms;

namespace MasterHideGUI
{
    public partial class EditForm : Form
    {
        private ProcessRule _processRule { get; set; }
        private List<Profile> _profiles { get; set; }
        private long _currentPolicyFlags { get; set; }

        public EditForm(ProcessRule processRule)
        {
            InitializeComponent();

            _currentPolicyFlags = (long)ProcessPolicyFlags.ProcessPolicyFlagNone;
            _processRule = processRule;
            _profiles = ProfileManager.LoadProfiles();

            ProfileManager.EnsureDefaultProfile(_profiles);

            RefreshProfiles();
            LoadCurrentProfile();
        }

        public ProcessRule GetProcessRule()
        {
            return _processRule;
        }

        private void LoadCurrentProfile()
        {
            int idx;

            if (string.IsNullOrEmpty(_processRule.ProfileName))
            {
                idx = _profiles.FindIndex(p => p.ProfileName == "Default");
                if (idx >= 0)
                {
                    comboBoxProfiles.SelectedIndex = idx;
                }
            }
            else
            {
                string currentProfileName = _processRule.ProfileName;
                idx = comboBoxProfiles.FindStringExact(currentProfileName);
                if (idx == -1)
                {
                    MessageBox.Show($"Failed to load profile {currentProfileName}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                comboBoxProfiles.SelectedIndex = idx;
            }
        }

        private void UpdateCheckboxes()
        {
            long policyFlags = _currentPolicyFlags;

            chkMonitor.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagMonitored) != 0;
            chkProtect.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagProtected) != 0;
            chkHideFromDebugger.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagHideFromDebugger) != 0;
            chkNtQuerySystemInformation.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtQuerySystemInformation) != 0;
            chkSpoofCodeIntegrity.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagHideSystemCodeIntegrity) != 0;
            chkBypassInstrumentationCallback.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagBypassInstrumentationCallback) != 0;
            chkNtQueryObject.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtQueryObject) != 0;
            chkNtYieldExecution.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtYieldExecution) != 0;
            chkNtClose.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtClose) != 0;
            chkNtSystemDebugControl.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtSystemDebugControl) != 0;
            chkNtQueryInformationProcess.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtQueryInformationProcess) != 0;
            chkNtSetInformationProcess.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtSetInformationProcess) != 0;
            chkNtQueryInformationJobObject.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtQueryInformationJobObject) != 0;
            chkNtGetNextProcess.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtGetNextProcess) != 0;
            chkBypassProcessFreeze.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagClearBypassProcessFreeze) != 0;
            chkBypassProcessBreakOnTermination.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagClearProcessBreakOnTerminationFlag) != 0;
            chkHidePEBBeingDebugged.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagClearPebBeingDebugged) != 0;
            chkHidePEBHeapFlags.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagClearHeapFlags) != 0;
            chkHidePEBNtGlobalFlag.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagClearPebNtGlobalFlag) != 0;
            chkHideKUserSharedData.Checked = ((policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagHideKUserSharedData) != 0 || (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagClearKUserSharedData) != 0);
            chkSaveDebugFlags.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagSaveProcessDebugFlags) != 0;
            chkSaveHandleTracingFlags.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagSaveProcessHandleTracing) != 0;
            chkNtCreateUserProcess.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtCreateUserProcess) != 0;
            chkHideChildFromDebugger.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagHideChildFromDebugger) != 0;
            chkNtQueryInformationThread.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtQueryInformationThread) != 0;
            chkNtSetInformationThread.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtSetInformationThread) != 0;
            chkNtCreateThreadEx.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtCreateThreadEx) != 0;
            chkBypassThreadBreakOnTermination.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagClearThreadBreakOnTerminationFlag) != 0;
            chkNtGetContextThread.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtGetContextThread) != 0;
            chkNtSetContextThread.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtSetContextThread) != 0;
            chkNtContinue.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtContinue) != 0;
            //chkKiDispatchException.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNone) != 0; // TODO: add
            chkNtQuerySystemTime.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtQuerySystemTime) != 0;
            chkNtQueryPerformanceCounter.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtQueryPerformanceCounter) != 0;
            chkNtUserBuildHwndList.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtUserBuildHwndList) != 0;
            chkNtUserFindWindowEx.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtUserFindWindowEx) != 0;
            chkNtUserGetForegroundWindow.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtUserGetForegroundWindow) != 0;
            chkNtUserQueryWindow.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtUserQueryWindow) != 0;
            chkNtUserWindowFromPoint.Checked = (policyFlags & (long)ProcessPolicyFlags.ProcessPolicyFlagNtUserWindowFromPoint) != 0;
        }

        private void RefreshProfiles()
        {
            comboBoxProfiles.SelectedIndexChanged -= ComboBoxProfiles_SelectedIndexChanged;

            comboBoxProfiles.DataSource = null;
            comboBoxProfiles.DataSource = _profiles;
            comboBoxProfiles.DisplayMember = "ProfileName";
            comboBoxProfiles.ValueMember = "PolicyFlags";

            comboBoxProfiles.SelectedIndexChanged += ComboBoxProfiles_SelectedIndexChanged;
        }

        private void ComboBoxProfiles_SelectedIndexChanged(object sender, EventArgs e)
        {
            bool isItemSelected = comboBoxProfiles.SelectedIndex >= 0;
            if (isItemSelected)
            {
                var selectedProfile = (Profile)comboBoxProfiles.SelectedItem;

                _processRule.SetProfileName(selectedProfile.ProfileName);
                _currentPolicyFlags = selectedProfile.PolicyFlags;

                UpdateCheckboxes();
            }

            btnDeleteProfile.Enabled = isItemSelected;
        }

        private void CheckBox_CheckedChanged(object sender, EventArgs e)
        {
            CheckBox checkBox = sender as CheckBox;
            ProcessPolicyFlags flag = ProcessPolicyFlags.ProcessPolicyFlagNone;

            if (checkBox == chkMonitor)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagMonitored;
            }
            else if (checkBox == chkHideFromDebugger)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagHideFromDebugger;
            }
            else if (checkBox == chkProtect)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagProtected;
            }
            else if (checkBox == chkNtQuerySystemInformation)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtQuerySystemInformation;
                chkSpoofCodeIntegrity.Enabled = checkBox.Checked;
            }
            else if (checkBox == chkSpoofCodeIntegrity)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagHideSystemCodeIntegrity;
            }
            else if (checkBox == chkBypassInstrumentationCallback)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagBypassInstrumentationCallback;
            }
            else if (checkBox == chkNtQueryObject)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtQueryObject;
            }
            else if (checkBox == chkNtYieldExecution)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtYieldExecution;
            }
            else if (checkBox == chkNtClose)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtClose;
            }
            else if (checkBox == chkNtSystemDebugControl)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtSystemDebugControl;
            }
            else if (checkBox == chkNtQueryInformationProcess)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtQueryInformationProcess;
            }
            else if (checkBox == chkNtSetInformationProcess)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtSetInformationProcess;
            }
            else if (checkBox == chkNtQueryInformationJobObject)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtQueryInformationJobObject;
            }
            else if (checkBox == chkNtGetNextProcess)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtGetNextProcess;
            }
            else if (checkBox == chkBypassProcessFreeze)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagClearBypassProcessFreeze;
            }
            else if (checkBox == chkBypassProcessBreakOnTermination)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagClearProcessBreakOnTerminationFlag;
            }
            else if (checkBox == chkHidePEBBeingDebugged)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagClearPebBeingDebugged;
            }
            else if (checkBox == chkHidePEBNtGlobalFlag)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagClearPebNtGlobalFlag;
            }
            else if (checkBox == chkHidePEBHeapFlags)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagClearHeapFlags;
            }
            else if (checkBox == chkHideKUserSharedData)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagHideKUserSharedData | ProcessPolicyFlags.ProcessPolicyFlagClearKUserSharedData;
            }
            else if (checkBox == chkSaveDebugFlags)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagSaveProcessDebugFlags;
            }
            else if (checkBox == chkSaveHandleTracingFlags)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagSaveProcessHandleTracing;
            }
            else if (checkBox == chkNtCreateUserProcess)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtCreateUserProcess;
                chkHideChildFromDebugger.Enabled = checkBox.Checked;
            }
            else if (checkBox == chkHideChildFromDebugger)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagHideChildFromDebugger;
            }
            else if (checkBox == chkNtSetInformationThread)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtSetInformationThread;
            }
            else if (checkBox == chkNtQueryInformationThread)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtQueryInformationThread;
            }
            else if (checkBox == chkNtCreateThreadEx)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtCreateThreadEx;
            }
            else if (checkBox == chkBypassThreadBreakOnTermination)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagClearThreadBreakOnTerminationFlag;
            }
            else if (checkBox == chkNtGetContextThread)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtGetContextThread;
            }
            else if (checkBox == chkNtSetContextThread)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtSetContextThread;
            }
            else if (checkBox == chkNtContinue)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtContinue;
            }
            else if (checkBox == chkKiDispatchException)
            {
                //flag = ProcessPolicyFlags.ProcessPolicyFlagNone; // TODO: add
            }
            else if (checkBox == chkNtQuerySystemTime)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtQuerySystemTime;
            }
            else if (checkBox == chkNtQueryPerformanceCounter)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtQueryPerformanceCounter;
            }
            else if (checkBox == chkNtUserFindWindowEx)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtUserFindWindowEx;
            }
            else if (checkBox == chkNtUserBuildHwndList)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtUserBuildHwndList;
            }
            else if (checkBox == chkNtUserGetForegroundWindow)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtUserGetForegroundWindow;
            }
            else if (checkBox == chkNtUserQueryWindow)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtUserQueryWindow;
            }
            else if (checkBox == chkNtUserWindowFromPoint)
            {
                flag = ProcessPolicyFlags.ProcessPolicyFlagNtUserWindowFromPoint;
            }

            if (checkBox.Checked)
            {
                _currentPolicyFlags |= (long)flag;
            }
            else
            {
                _currentPolicyFlags &= ~(long)flag;
            }
        }

        private void btnClose_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }

        private void btnSave_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(_processRule.ProfileName))
            {
                int idx = _profiles.FindIndex(p => p.ProfileName == _processRule.ProfileName);
                if (idx >= 0)
                {
                    // Update the profile policy flags and save it
                    //
                    var profile = _profiles[idx];
                    profile.PolicyFlags = _currentPolicyFlags;

                    _profiles[idx] = profile;
                    ProfileManager.SaveProfiles(_profiles);
                }
            }

            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void btnAddProfile_Click(object sender, EventArgs e)
        {
            var createProfileForm = new CreateProfileForm();
            if (createProfileForm.ShowDialog() == DialogResult.OK)
            {
                string newProfileName = createProfileForm.GetProfileName();

                if (_profiles.Exists(p => p.ProfileName == newProfileName))
                {
                    MessageBox.Show($"Profile with name {newProfileName} already exists!", "Cannot create profile", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                var profile = new Profile { ProfileName = createProfileForm.GetProfileName(), PolicyFlags = _currentPolicyFlags };

                _profiles.Add(profile);
                ProfileManager.SaveProfiles(_profiles);
                RefreshProfiles();

                comboBoxProfiles.SelectedItem = profile;
            }
        }

        private void btnDeleteProfile_Click(object sender, EventArgs e)
        {
            if (comboBoxProfiles.SelectedIndex >= 0)
            {
                int selectedIndex = comboBoxProfiles.SelectedIndex;
                var selectedProfile = (Profile)comboBoxProfiles.SelectedItem;

                if (selectedProfile.ProfileName == "Default")
                {
                    MessageBox.Show("You cannot delete the default profile!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (MessageBox.Show($"Are you sure you wanna delete profile {selectedProfile.ProfileName}?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                {
                    _profiles.Remove(selectedProfile);
                    ProfileManager.SaveProfiles(_profiles);
                    RefreshProfiles();

                    if (_profiles.Count > 0)
                    {
                        int newIndex = selectedIndex < _profiles.Count ? selectedIndex : _profiles.Count - 1;
                        comboBoxProfiles.SelectedIndex = newIndex;
                    }
                }
            }
        }
    }
}
