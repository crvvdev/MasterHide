
namespace MasterHideGUI
{
    partial class EditForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.comboBoxProfiles = new System.Windows.Forms.ComboBox();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.btnDeleteProfile = new System.Windows.Forms.Button();
            this.btnAddProfile = new System.Windows.Forms.Button();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.chkMonitor = new System.Windows.Forms.CheckBox();
            this.chkProtect = new System.Windows.Forms.CheckBox();
            this.chkHideFromDebugger = new System.Windows.Forms.CheckBox();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.groupBox9 = new System.Windows.Forms.GroupBox();
            this.chkNtUserBuildHwndList = new System.Windows.Forms.CheckBox();
            this.chkNtUserFindWindowEx = new System.Windows.Forms.CheckBox();
            this.chkNtUserQueryWindow = new System.Windows.Forms.CheckBox();
            this.chkNtUserWindowFromPoint = new System.Windows.Forms.CheckBox();
            this.chkNtUserGetForegroundWindow = new System.Windows.Forms.CheckBox();
            this.groupBox8 = new System.Windows.Forms.GroupBox();
            this.chkNtCreateUserProcess = new System.Windows.Forms.CheckBox();
            this.chkNtGetNextProcess = new System.Windows.Forms.CheckBox();
            this.chkHideChildFromDebugger = new System.Windows.Forms.CheckBox();
            this.chkSaveHandleTracingFlags = new System.Windows.Forms.CheckBox();
            this.chkSaveDebugFlags = new System.Windows.Forms.CheckBox();
            this.chkBypassProcessBreakOnTermination = new System.Windows.Forms.CheckBox();
            this.chkHideKUserSharedData = new System.Windows.Forms.CheckBox();
            this.chkHidePEBHeapFlags = new System.Windows.Forms.CheckBox();
            this.chkHidePEBNtGlobalFlag = new System.Windows.Forms.CheckBox();
            this.chkHidePEBBeingDebugged = new System.Windows.Forms.CheckBox();
            this.chkBypassProcessFreeze = new System.Windows.Forms.CheckBox();
            this.chkNtQueryInformationProcess = new System.Windows.Forms.CheckBox();
            this.chkNtSetInformationProcess = new System.Windows.Forms.CheckBox();
            this.chkNtQueryInformationJobObject = new System.Windows.Forms.CheckBox();
            this.groupBox7 = new System.Windows.Forms.GroupBox();
            this.chkNtSystemDebugControl = new System.Windows.Forms.CheckBox();
            this.chkNtClose = new System.Windows.Forms.CheckBox();
            this.chkNtQuerySystemInformation = new System.Windows.Forms.CheckBox();
            this.chkSpoofCodeIntegrity = new System.Windows.Forms.CheckBox();
            this.chkNtYieldExecution = new System.Windows.Forms.CheckBox();
            this.chkNtQueryObject = new System.Windows.Forms.CheckBox();
            this.groupBox6 = new System.Windows.Forms.GroupBox();
            this.chkNtCreateThreadEx = new System.Windows.Forms.CheckBox();
            this.chkBypassThreadBreakOnTermination = new System.Windows.Forms.CheckBox();
            this.chkNtSetInformationThread = new System.Windows.Forms.CheckBox();
            this.chkNtQueryInformationThread = new System.Windows.Forms.CheckBox();
            this.groupBox4 = new System.Windows.Forms.GroupBox();
            this.chkKiDispatchException = new System.Windows.Forms.CheckBox();
            this.chkNtContinue = new System.Windows.Forms.CheckBox();
            this.chkNtSetContextThread = new System.Windows.Forms.CheckBox();
            this.chkNtGetContextThread = new System.Windows.Forms.CheckBox();
            this.groupBox5 = new System.Windows.Forms.GroupBox();
            this.chkNtQueryPerformanceCounter = new System.Windows.Forms.CheckBox();
            this.chkNtQuerySystemTime = new System.Windows.Forms.CheckBox();
            this.btnSave = new System.Windows.Forms.Button();
            this.btnClose = new System.Windows.Forms.Button();
            this.chkBypassInstrumentationCallback = new System.Windows.Forms.CheckBox();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.groupBox9.SuspendLayout();
            this.groupBox8.SuspendLayout();
            this.groupBox7.SuspendLayout();
            this.groupBox6.SuspendLayout();
            this.groupBox4.SuspendLayout();
            this.groupBox5.SuspendLayout();
            this.SuspendLayout();
            // 
            // comboBoxProfiles
            // 
            this.comboBoxProfiles.FormattingEnabled = true;
            this.comboBoxProfiles.Location = new System.Drawing.Point(13, 19);
            this.comboBoxProfiles.Name = "comboBoxProfiles";
            this.comboBoxProfiles.Size = new System.Drawing.Size(328, 21);
            this.comboBoxProfiles.TabIndex = 0;
            this.comboBoxProfiles.SelectedIndexChanged += new System.EventHandler(this.ComboBoxProfiles_SelectedIndexChanged);
            // 
            // groupBox1
            // 
            this.groupBox1.AutoSize = true;
            this.groupBox1.Controls.Add(this.btnDeleteProfile);
            this.groupBox1.Controls.Add(this.btnAddProfile);
            this.groupBox1.Controls.Add(this.comboBoxProfiles);
            this.groupBox1.Location = new System.Drawing.Point(12, 12);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(516, 61);
            this.groupBox1.TabIndex = 1;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Profiles";
            // 
            // btnDeleteProfile
            // 
            this.btnDeleteProfile.Enabled = false;
            this.btnDeleteProfile.Location = new System.Drawing.Point(435, 19);
            this.btnDeleteProfile.Name = "btnDeleteProfile";
            this.btnDeleteProfile.Size = new System.Drawing.Size(75, 23);
            this.btnDeleteProfile.TabIndex = 2;
            this.btnDeleteProfile.Text = "Delete";
            this.btnDeleteProfile.UseVisualStyleBackColor = true;
            this.btnDeleteProfile.Click += new System.EventHandler(this.btnDeleteProfile_Click);
            // 
            // btnAddProfile
            // 
            this.btnAddProfile.Location = new System.Drawing.Point(354, 19);
            this.btnAddProfile.Name = "btnAddProfile";
            this.btnAddProfile.Size = new System.Drawing.Size(75, 23);
            this.btnAddProfile.TabIndex = 1;
            this.btnAddProfile.Text = "Add";
            this.btnAddProfile.UseVisualStyleBackColor = true;
            this.btnAddProfile.Click += new System.EventHandler(this.btnAddProfile_Click);
            // 
            // groupBox2
            // 
            this.groupBox2.AutoSize = true;
            this.groupBox2.Controls.Add(this.chkMonitor);
            this.groupBox2.Controls.Add(this.chkProtect);
            this.groupBox2.Controls.Add(this.chkHideFromDebugger);
            this.groupBox2.Location = new System.Drawing.Point(12, 75);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(515, 55);
            this.groupBox2.TabIndex = 2;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "General Flags";
            // 
            // chkMonitor
            // 
            this.chkMonitor.AutoSize = true;
            this.chkMonitor.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkMonitor.Location = new System.Drawing.Point(421, 19);
            this.chkMonitor.Name = "chkMonitor";
            this.chkMonitor.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkMonitor.Size = new System.Drawing.Size(61, 17);
            this.chkMonitor.TabIndex = 2;
            this.chkMonitor.Text = "Monitor";
            this.chkMonitor.UseVisualStyleBackColor = true;
            this.chkMonitor.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkProtect
            // 
            this.chkProtect.AutoSize = true;
            this.chkProtect.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkProtect.Location = new System.Drawing.Point(236, 19);
            this.chkProtect.Name = "chkProtect";
            this.chkProtect.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkProtect.Size = new System.Drawing.Size(60, 17);
            this.chkProtect.TabIndex = 1;
            this.chkProtect.Text = "Protect";
            this.chkProtect.UseVisualStyleBackColor = true;
            this.chkProtect.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkHideFromDebugger
            // 
            this.chkHideFromDebugger.AutoSize = true;
            this.chkHideFromDebugger.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkHideFromDebugger.Location = new System.Drawing.Point(13, 19);
            this.chkHideFromDebugger.Name = "chkHideFromDebugger";
            this.chkHideFromDebugger.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkHideFromDebugger.Size = new System.Drawing.Size(121, 17);
            this.chkHideFromDebugger.TabIndex = 0;
            this.chkHideFromDebugger.Text = "Hide from Debugger";
            this.chkHideFromDebugger.UseVisualStyleBackColor = true;
            this.chkHideFromDebugger.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // groupBox3
            // 
            this.groupBox3.AutoSize = true;
            this.groupBox3.Controls.Add(this.groupBox9);
            this.groupBox3.Controls.Add(this.groupBox8);
            this.groupBox3.Controls.Add(this.groupBox7);
            this.groupBox3.Controls.Add(this.groupBox6);
            this.groupBox3.Controls.Add(this.groupBox4);
            this.groupBox3.Controls.Add(this.groupBox5);
            this.groupBox3.Location = new System.Drawing.Point(12, 136);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(515, 640);
            this.groupBox3.TabIndex = 3;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "General configuration";
            // 
            // groupBox9
            // 
            this.groupBox9.Controls.Add(this.chkNtUserBuildHwndList);
            this.groupBox9.Controls.Add(this.chkNtUserFindWindowEx);
            this.groupBox9.Controls.Add(this.chkNtUserQueryWindow);
            this.groupBox9.Controls.Add(this.chkNtUserWindowFromPoint);
            this.groupBox9.Controls.Add(this.chkNtUserGetForegroundWindow);
            this.groupBox9.Location = new System.Drawing.Point(13, 521);
            this.groupBox9.Name = "groupBox9";
            this.groupBox9.Size = new System.Drawing.Size(490, 100);
            this.groupBox9.TabIndex = 18;
            this.groupBox9.TabStop = false;
            this.groupBox9.Text = "HWND";
            // 
            // chkNtUserBuildHwndList
            // 
            this.chkNtUserBuildHwndList.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtUserBuildHwndList.Location = new System.Drawing.Point(261, 42);
            this.chkNtUserBuildHwndList.Name = "chkNtUserBuildHwndList";
            this.chkNtUserBuildHwndList.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtUserBuildHwndList.Size = new System.Drawing.Size(208, 17);
            this.chkNtUserBuildHwndList.TabIndex = 18;
            this.chkNtUserBuildHwndList.Text = "NtUserBuildHwndList";
            this.chkNtUserBuildHwndList.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtUserBuildHwndList.UseVisualStyleBackColor = true;
            this.chkNtUserBuildHwndList.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtUserFindWindowEx
            // 
            this.chkNtUserFindWindowEx.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtUserFindWindowEx.Location = new System.Drawing.Point(261, 19);
            this.chkNtUserFindWindowEx.Name = "chkNtUserFindWindowEx";
            this.chkNtUserFindWindowEx.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtUserFindWindowEx.Size = new System.Drawing.Size(208, 17);
            this.chkNtUserFindWindowEx.TabIndex = 17;
            this.chkNtUserFindWindowEx.Text = "NtUserFindWindowEx";
            this.chkNtUserFindWindowEx.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtUserFindWindowEx.UseVisualStyleBackColor = true;
            this.chkNtUserFindWindowEx.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtUserQueryWindow
            // 
            this.chkNtUserQueryWindow.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtUserQueryWindow.Location = new System.Drawing.Point(13, 65);
            this.chkNtUserQueryWindow.Name = "chkNtUserQueryWindow";
            this.chkNtUserQueryWindow.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtUserQueryWindow.Size = new System.Drawing.Size(208, 17);
            this.chkNtUserQueryWindow.TabIndex = 16;
            this.chkNtUserQueryWindow.Text = "NtUserQueryWindow";
            this.chkNtUserQueryWindow.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtUserQueryWindow.UseVisualStyleBackColor = true;
            this.chkNtUserQueryWindow.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtUserWindowFromPoint
            // 
            this.chkNtUserWindowFromPoint.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtUserWindowFromPoint.Location = new System.Drawing.Point(13, 42);
            this.chkNtUserWindowFromPoint.Name = "chkNtUserWindowFromPoint";
            this.chkNtUserWindowFromPoint.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtUserWindowFromPoint.Size = new System.Drawing.Size(208, 17);
            this.chkNtUserWindowFromPoint.TabIndex = 15;
            this.chkNtUserWindowFromPoint.Text = "NtUserWindowFromPoint";
            this.chkNtUserWindowFromPoint.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtUserWindowFromPoint.UseVisualStyleBackColor = true;
            this.chkNtUserWindowFromPoint.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtUserGetForegroundWindow
            // 
            this.chkNtUserGetForegroundWindow.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtUserGetForegroundWindow.Location = new System.Drawing.Point(13, 19);
            this.chkNtUserGetForegroundWindow.Name = "chkNtUserGetForegroundWindow";
            this.chkNtUserGetForegroundWindow.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtUserGetForegroundWindow.Size = new System.Drawing.Size(208, 17);
            this.chkNtUserGetForegroundWindow.TabIndex = 14;
            this.chkNtUserGetForegroundWindow.Text = "NtUserGetForegroundWindow";
            this.chkNtUserGetForegroundWindow.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtUserGetForegroundWindow.UseVisualStyleBackColor = true;
            this.chkNtUserGetForegroundWindow.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // groupBox8
            // 
            this.groupBox8.AutoSize = true;
            this.groupBox8.Controls.Add(this.chkBypassInstrumentationCallback);
            this.groupBox8.Controls.Add(this.chkNtCreateUserProcess);
            this.groupBox8.Controls.Add(this.chkNtGetNextProcess);
            this.groupBox8.Controls.Add(this.chkHideChildFromDebugger);
            this.groupBox8.Controls.Add(this.chkSaveHandleTracingFlags);
            this.groupBox8.Controls.Add(this.chkSaveDebugFlags);
            this.groupBox8.Controls.Add(this.chkBypassProcessBreakOnTermination);
            this.groupBox8.Controls.Add(this.chkHideKUserSharedData);
            this.groupBox8.Controls.Add(this.chkHidePEBHeapFlags);
            this.groupBox8.Controls.Add(this.chkHidePEBNtGlobalFlag);
            this.groupBox8.Controls.Add(this.chkHidePEBBeingDebugged);
            this.groupBox8.Controls.Add(this.chkBypassProcessFreeze);
            this.groupBox8.Controls.Add(this.chkNtQueryInformationProcess);
            this.groupBox8.Controls.Add(this.chkNtSetInformationProcess);
            this.groupBox8.Controls.Add(this.chkNtQueryInformationJobObject);
            this.groupBox8.Location = new System.Drawing.Point(13, 148);
            this.groupBox8.Name = "groupBox8";
            this.groupBox8.Size = new System.Drawing.Size(238, 367);
            this.groupBox8.TabIndex = 17;
            this.groupBox8.TabStop = false;
            this.groupBox8.Text = "Process";
            // 
            // chkNtCreateUserProcess
            // 
            this.chkNtCreateUserProcess.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtCreateUserProcess.Location = new System.Drawing.Point(13, 308);
            this.chkNtCreateUserProcess.Name = "chkNtCreateUserProcess";
            this.chkNtCreateUserProcess.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtCreateUserProcess.Size = new System.Drawing.Size(208, 17);
            this.chkNtCreateUserProcess.TabIndex = 16;
            this.chkNtCreateUserProcess.Text = "NtCreateUserProcess";
            this.chkNtCreateUserProcess.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtCreateUserProcess.UseVisualStyleBackColor = true;
            this.chkNtCreateUserProcess.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtGetNextProcess
            // 
            this.chkNtGetNextProcess.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtGetNextProcess.Location = new System.Drawing.Point(13, 108);
            this.chkNtGetNextProcess.Name = "chkNtGetNextProcess";
            this.chkNtGetNextProcess.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtGetNextProcess.Size = new System.Drawing.Size(208, 17);
            this.chkNtGetNextProcess.TabIndex = 22;
            this.chkNtGetNextProcess.Text = "NtGetNextProcess";
            this.chkNtGetNextProcess.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtGetNextProcess.UseVisualStyleBackColor = true;
            this.chkNtGetNextProcess.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkHideChildFromDebugger
            // 
            this.chkHideChildFromDebugger.Enabled = false;
            this.chkHideChildFromDebugger.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkHideChildFromDebugger.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkHideChildFromDebugger.ImageAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkHideChildFromDebugger.Location = new System.Drawing.Point(18, 331);
            this.chkHideChildFromDebugger.Name = "chkHideChildFromDebugger";
            this.chkHideChildFromDebugger.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkHideChildFromDebugger.Size = new System.Drawing.Size(203, 17);
            this.chkHideChildFromDebugger.TabIndex = 21;
            this.chkHideChildFromDebugger.Text = "Hide child from debugger *";
            this.chkHideChildFromDebugger.UseVisualStyleBackColor = true;
            this.chkHideChildFromDebugger.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkSaveHandleTracingFlags
            // 
            this.chkSaveHandleTracingFlags.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkSaveHandleTracingFlags.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkSaveHandleTracingFlags.ImageAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkSaveHandleTracingFlags.Location = new System.Drawing.Point(13, 285);
            this.chkSaveHandleTracingFlags.Name = "chkSaveHandleTracingFlags";
            this.chkSaveHandleTracingFlags.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkSaveHandleTracingFlags.Size = new System.Drawing.Size(208, 17);
            this.chkSaveHandleTracingFlags.TabIndex = 20;
            this.chkSaveHandleTracingFlags.Text = "Save handle tracing flags *";
            this.chkSaveHandleTracingFlags.UseVisualStyleBackColor = true;
            this.chkSaveHandleTracingFlags.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkSaveDebugFlags
            // 
            this.chkSaveDebugFlags.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkSaveDebugFlags.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkSaveDebugFlags.ImageAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkSaveDebugFlags.Location = new System.Drawing.Point(18, 264);
            this.chkSaveDebugFlags.Name = "chkSaveDebugFlags";
            this.chkSaveDebugFlags.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkSaveDebugFlags.Size = new System.Drawing.Size(203, 17);
            this.chkSaveDebugFlags.TabIndex = 19;
            this.chkSaveDebugFlags.Text = "Save debug flags *";
            this.chkSaveDebugFlags.UseVisualStyleBackColor = true;
            this.chkSaveDebugFlags.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkBypassProcessBreakOnTermination
            // 
            this.chkBypassProcessBreakOnTermination.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkBypassProcessBreakOnTermination.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkBypassProcessBreakOnTermination.ImageAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkBypassProcessBreakOnTermination.Location = new System.Drawing.Point(13, 151);
            this.chkBypassProcessBreakOnTermination.Name = "chkBypassProcessBreakOnTermination";
            this.chkBypassProcessBreakOnTermination.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkBypassProcessBreakOnTermination.Size = new System.Drawing.Size(208, 22);
            this.chkBypassProcessBreakOnTermination.TabIndex = 18;
            this.chkBypassProcessBreakOnTermination.Text = "Bypass ProcessBreakOnTermination *";
            this.chkBypassProcessBreakOnTermination.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkBypassProcessBreakOnTermination.UseVisualStyleBackColor = true;
            this.chkBypassProcessBreakOnTermination.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkHideKUserSharedData
            // 
            this.chkHideKUserSharedData.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkHideKUserSharedData.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkHideKUserSharedData.Location = new System.Drawing.Point(38, 242);
            this.chkHideKUserSharedData.Name = "chkHideKUserSharedData";
            this.chkHideKUserSharedData.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkHideKUserSharedData.Size = new System.Drawing.Size(183, 17);
            this.chkHideKUserSharedData.TabIndex = 17;
            this.chkHideKUserSharedData.Text = "Hide KUserSharedData *";
            this.chkHideKUserSharedData.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkHideKUserSharedData.UseVisualStyleBackColor = true;
            this.chkHideKUserSharedData.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkHidePEBHeapFlags
            // 
            this.chkHidePEBHeapFlags.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkHidePEBHeapFlags.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkHidePEBHeapFlags.Location = new System.Drawing.Point(38, 219);
            this.chkHidePEBHeapFlags.Name = "chkHidePEBHeapFlags";
            this.chkHidePEBHeapFlags.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkHidePEBHeapFlags.Size = new System.Drawing.Size(183, 17);
            this.chkHidePEBHeapFlags.TabIndex = 16;
            this.chkHidePEBHeapFlags.Text = "Hide PEB->HeapFlags *";
            this.chkHidePEBHeapFlags.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkHidePEBHeapFlags.UseVisualStyleBackColor = true;
            this.chkHidePEBHeapFlags.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkHidePEBNtGlobalFlag
            // 
            this.chkHidePEBNtGlobalFlag.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkHidePEBNtGlobalFlag.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkHidePEBNtGlobalFlag.Location = new System.Drawing.Point(38, 197);
            this.chkHidePEBNtGlobalFlag.Name = "chkHidePEBNtGlobalFlag";
            this.chkHidePEBNtGlobalFlag.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkHidePEBNtGlobalFlag.Size = new System.Drawing.Size(183, 17);
            this.chkHidePEBNtGlobalFlag.TabIndex = 15;
            this.chkHidePEBNtGlobalFlag.Text = "Hide PEB->NtGlobalFlag *";
            this.chkHidePEBNtGlobalFlag.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkHidePEBNtGlobalFlag.UseVisualStyleBackColor = true;
            this.chkHidePEBNtGlobalFlag.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkHidePEBBeingDebugged
            // 
            this.chkHidePEBBeingDebugged.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkHidePEBBeingDebugged.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkHidePEBBeingDebugged.Location = new System.Drawing.Point(38, 176);
            this.chkHidePEBBeingDebugged.Name = "chkHidePEBBeingDebugged";
            this.chkHidePEBBeingDebugged.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkHidePEBBeingDebugged.Size = new System.Drawing.Size(183, 17);
            this.chkHidePEBBeingDebugged.TabIndex = 14;
            this.chkHidePEBBeingDebugged.Text = "Hide PEB->BeingDebugged *";
            this.chkHidePEBBeingDebugged.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkHidePEBBeingDebugged.UseVisualStyleBackColor = true;
            this.chkHidePEBBeingDebugged.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkBypassProcessFreeze
            // 
            this.chkBypassProcessFreeze.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkBypassProcessFreeze.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkBypassProcessFreeze.Location = new System.Drawing.Point(13, 131);
            this.chkBypassProcessFreeze.Name = "chkBypassProcessFreeze";
            this.chkBypassProcessFreeze.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkBypassProcessFreeze.Size = new System.Drawing.Size(208, 17);
            this.chkBypassProcessFreeze.TabIndex = 13;
            this.chkBypassProcessFreeze.Text = "Bypass process freeze *";
            this.chkBypassProcessFreeze.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkBypassProcessFreeze.UseVisualStyleBackColor = true;
            this.chkBypassProcessFreeze.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtQueryInformationProcess
            // 
            this.chkNtQueryInformationProcess.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtQueryInformationProcess.Location = new System.Drawing.Point(13, 19);
            this.chkNtQueryInformationProcess.Name = "chkNtQueryInformationProcess";
            this.chkNtQueryInformationProcess.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtQueryInformationProcess.Size = new System.Drawing.Size(208, 17);
            this.chkNtQueryInformationProcess.TabIndex = 8;
            this.chkNtQueryInformationProcess.Text = "NtQueryInformationProcess";
            this.chkNtQueryInformationProcess.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtQueryInformationProcess.UseVisualStyleBackColor = true;
            this.chkNtQueryInformationProcess.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtSetInformationProcess
            // 
            this.chkNtSetInformationProcess.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtSetInformationProcess.Location = new System.Drawing.Point(13, 41);
            this.chkNtSetInformationProcess.Name = "chkNtSetInformationProcess";
            this.chkNtSetInformationProcess.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtSetInformationProcess.Size = new System.Drawing.Size(208, 17);
            this.chkNtSetInformationProcess.TabIndex = 9;
            this.chkNtSetInformationProcess.Text = "NtSetInformationProcess";
            this.chkNtSetInformationProcess.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtSetInformationProcess.UseVisualStyleBackColor = true;
            this.chkNtSetInformationProcess.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtQueryInformationJobObject
            // 
            this.chkNtQueryInformationJobObject.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtQueryInformationJobObject.Location = new System.Drawing.Point(13, 85);
            this.chkNtQueryInformationJobObject.Name = "chkNtQueryInformationJobObject";
            this.chkNtQueryInformationJobObject.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtQueryInformationJobObject.Size = new System.Drawing.Size(208, 17);
            this.chkNtQueryInformationJobObject.TabIndex = 11;
            this.chkNtQueryInformationJobObject.Text = "NtQueryInformationJobObject";
            this.chkNtQueryInformationJobObject.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtQueryInformationJobObject.UseVisualStyleBackColor = true;
            this.chkNtQueryInformationJobObject.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // groupBox7
            // 
            this.groupBox7.AutoSize = true;
            this.groupBox7.Controls.Add(this.chkNtSystemDebugControl);
            this.groupBox7.Controls.Add(this.chkNtClose);
            this.groupBox7.Controls.Add(this.chkNtQuerySystemInformation);
            this.groupBox7.Controls.Add(this.chkSpoofCodeIntegrity);
            this.groupBox7.Controls.Add(this.chkNtYieldExecution);
            this.groupBox7.Controls.Add(this.chkNtQueryObject);
            this.groupBox7.Location = new System.Drawing.Point(13, 19);
            this.groupBox7.Name = "groupBox7";
            this.groupBox7.Size = new System.Drawing.Size(490, 124);
            this.groupBox7.TabIndex = 16;
            this.groupBox7.TabStop = false;
            this.groupBox7.Text = "System/objects";
            // 
            // chkNtSystemDebugControl
            // 
            this.chkNtSystemDebugControl.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtSystemDebugControl.Location = new System.Drawing.Point(13, 68);
            this.chkNtSystemDebugControl.Name = "chkNtSystemDebugControl";
            this.chkNtSystemDebugControl.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtSystemDebugControl.Size = new System.Drawing.Size(208, 17);
            this.chkNtSystemDebugControl.TabIndex = 14;
            this.chkNtSystemDebugControl.Text = "NtSystemDebugControl";
            this.chkNtSystemDebugControl.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtSystemDebugControl.UseVisualStyleBackColor = true;
            this.chkNtSystemDebugControl.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtClose
            // 
            this.chkNtClose.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtClose.Location = new System.Drawing.Point(261, 45);
            this.chkNtClose.Name = "chkNtClose";
            this.chkNtClose.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtClose.Size = new System.Drawing.Size(208, 17);
            this.chkNtClose.TabIndex = 13;
            this.chkNtClose.Text = "NtClose";
            this.chkNtClose.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtClose.UseVisualStyleBackColor = true;
            this.chkNtClose.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtQuerySystemInformation
            // 
            this.chkNtQuerySystemInformation.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtQuerySystemInformation.Location = new System.Drawing.Point(18, 22);
            this.chkNtQuerySystemInformation.Name = "chkNtQuerySystemInformation";
            this.chkNtQuerySystemInformation.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtQuerySystemInformation.Size = new System.Drawing.Size(203, 17);
            this.chkNtQuerySystemInformation.TabIndex = 3;
            this.chkNtQuerySystemInformation.Text = "NtQuerySystemInformation";
            this.chkNtQuerySystemInformation.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtQuerySystemInformation.UseVisualStyleBackColor = true;
            this.chkNtQuerySystemInformation.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkSpoofCodeIntegrity
            // 
            this.chkSpoofCodeIntegrity.Enabled = false;
            this.chkSpoofCodeIntegrity.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkSpoofCodeIntegrity.Location = new System.Drawing.Point(65, 45);
            this.chkSpoofCodeIntegrity.Name = "chkSpoofCodeIntegrity";
            this.chkSpoofCodeIntegrity.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkSpoofCodeIntegrity.Size = new System.Drawing.Size(156, 17);
            this.chkSpoofCodeIntegrity.TabIndex = 4;
            this.chkSpoofCodeIntegrity.Text = "Spoof code integrity *";
            this.chkSpoofCodeIntegrity.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkSpoofCodeIntegrity.UseVisualStyleBackColor = true;
            this.chkSpoofCodeIntegrity.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtYieldExecution
            // 
            this.chkNtYieldExecution.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtYieldExecution.Location = new System.Drawing.Point(261, 68);
            this.chkNtYieldExecution.Name = "chkNtYieldExecution";
            this.chkNtYieldExecution.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtYieldExecution.Size = new System.Drawing.Size(208, 17);
            this.chkNtYieldExecution.TabIndex = 12;
            this.chkNtYieldExecution.Text = "NtYieldExecution";
            this.chkNtYieldExecution.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtYieldExecution.UseVisualStyleBackColor = true;
            this.chkNtYieldExecution.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtQueryObject
            // 
            this.chkNtQueryObject.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtQueryObject.Location = new System.Drawing.Point(261, 19);
            this.chkNtQueryObject.Name = "chkNtQueryObject";
            this.chkNtQueryObject.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtQueryObject.Size = new System.Drawing.Size(208, 17);
            this.chkNtQueryObject.TabIndex = 10;
            this.chkNtQueryObject.Text = "NtQueryObject";
            this.chkNtQueryObject.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtQueryObject.UseVisualStyleBackColor = true;
            this.chkNtQueryObject.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // groupBox6
            // 
            this.groupBox6.AutoSize = true;
            this.groupBox6.Controls.Add(this.chkNtCreateThreadEx);
            this.groupBox6.Controls.Add(this.chkBypassThreadBreakOnTermination);
            this.groupBox6.Controls.Add(this.chkNtSetInformationThread);
            this.groupBox6.Controls.Add(this.chkNtQueryInformationThread);
            this.groupBox6.Location = new System.Drawing.Point(261, 148);
            this.groupBox6.Name = "groupBox6";
            this.groupBox6.Size = new System.Drawing.Size(242, 126);
            this.groupBox6.TabIndex = 15;
            this.groupBox6.TabStop = false;
            this.groupBox6.Text = "Threads";
            // 
            // chkNtCreateThreadEx
            // 
            this.chkNtCreateThreadEx.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtCreateThreadEx.Location = new System.Drawing.Point(13, 65);
            this.chkNtCreateThreadEx.Name = "chkNtCreateThreadEx";
            this.chkNtCreateThreadEx.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtCreateThreadEx.Size = new System.Drawing.Size(208, 17);
            this.chkNtCreateThreadEx.TabIndex = 20;
            this.chkNtCreateThreadEx.Text = "NtCreateThreadEx";
            this.chkNtCreateThreadEx.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtCreateThreadEx.UseVisualStyleBackColor = true;
            this.chkNtCreateThreadEx.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkBypassThreadBreakOnTermination
            // 
            this.chkBypassThreadBreakOnTermination.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkBypassThreadBreakOnTermination.ForeColor = System.Drawing.SystemColors.ControlText;
            this.chkBypassThreadBreakOnTermination.Location = new System.Drawing.Point(13, 85);
            this.chkBypassThreadBreakOnTermination.Name = "chkBypassThreadBreakOnTermination";
            this.chkBypassThreadBreakOnTermination.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkBypassThreadBreakOnTermination.Size = new System.Drawing.Size(208, 22);
            this.chkBypassThreadBreakOnTermination.TabIndex = 19;
            this.chkBypassThreadBreakOnTermination.Text = "Bypass ThreadBreakOnTermination *";
            this.chkBypassThreadBreakOnTermination.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkBypassThreadBreakOnTermination.UseVisualStyleBackColor = true;
            this.chkBypassThreadBreakOnTermination.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtSetInformationThread
            // 
            this.chkNtSetInformationThread.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtSetInformationThread.Location = new System.Drawing.Point(13, 42);
            this.chkNtSetInformationThread.Name = "chkNtSetInformationThread";
            this.chkNtSetInformationThread.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtSetInformationThread.Size = new System.Drawing.Size(208, 17);
            this.chkNtSetInformationThread.TabIndex = 6;
            this.chkNtSetInformationThread.Text = "NtSetInformationThread";
            this.chkNtSetInformationThread.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtSetInformationThread.UseVisualStyleBackColor = true;
            this.chkNtSetInformationThread.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtQueryInformationThread
            // 
            this.chkNtQueryInformationThread.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtQueryInformationThread.Location = new System.Drawing.Point(13, 19);
            this.chkNtQueryInformationThread.Name = "chkNtQueryInformationThread";
            this.chkNtQueryInformationThread.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtQueryInformationThread.Size = new System.Drawing.Size(208, 17);
            this.chkNtQueryInformationThread.TabIndex = 7;
            this.chkNtQueryInformationThread.Text = "NtQueryInformationThread";
            this.chkNtQueryInformationThread.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtQueryInformationThread.UseVisualStyleBackColor = true;
            this.chkNtQueryInformationThread.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // groupBox4
            // 
            this.groupBox4.AutoSize = true;
            this.groupBox4.Controls.Add(this.chkKiDispatchException);
            this.groupBox4.Controls.Add(this.chkNtContinue);
            this.groupBox4.Controls.Add(this.chkNtSetContextThread);
            this.groupBox4.Controls.Add(this.chkNtGetContextThread);
            this.groupBox4.Location = new System.Drawing.Point(261, 280);
            this.groupBox4.Name = "groupBox4";
            this.groupBox4.Size = new System.Drawing.Size(242, 124);
            this.groupBox4.TabIndex = 4;
            this.groupBox4.TabStop = false;
            this.groupBox4.Text = "DRx protection";
            // 
            // chkKiDispatchException
            // 
            this.chkKiDispatchException.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkKiDispatchException.Location = new System.Drawing.Point(13, 88);
            this.chkKiDispatchException.Name = "chkKiDispatchException";
            this.chkKiDispatchException.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkKiDispatchException.Size = new System.Drawing.Size(208, 17);
            this.chkKiDispatchException.TabIndex = 7;
            this.chkKiDispatchException.Text = "KiDispatchException";
            this.chkKiDispatchException.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkKiDispatchException.UseVisualStyleBackColor = true;
            this.chkKiDispatchException.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtContinue
            // 
            this.chkNtContinue.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtContinue.Location = new System.Drawing.Point(13, 65);
            this.chkNtContinue.Name = "chkNtContinue";
            this.chkNtContinue.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtContinue.Size = new System.Drawing.Size(208, 17);
            this.chkNtContinue.TabIndex = 6;
            this.chkNtContinue.Text = "NtContinue";
            this.chkNtContinue.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtContinue.UseVisualStyleBackColor = true;
            this.chkNtContinue.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtSetContextThread
            // 
            this.chkNtSetContextThread.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtSetContextThread.Location = new System.Drawing.Point(12, 42);
            this.chkNtSetContextThread.Name = "chkNtSetContextThread";
            this.chkNtSetContextThread.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtSetContextThread.Size = new System.Drawing.Size(209, 17);
            this.chkNtSetContextThread.TabIndex = 5;
            this.chkNtSetContextThread.Text = "NtSetContextThread";
            this.chkNtSetContextThread.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtSetContextThread.UseVisualStyleBackColor = true;
            this.chkNtSetContextThread.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtGetContextThread
            // 
            this.chkNtGetContextThread.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtGetContextThread.Location = new System.Drawing.Point(13, 19);
            this.chkNtGetContextThread.Name = "chkNtGetContextThread";
            this.chkNtGetContextThread.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtGetContextThread.Size = new System.Drawing.Size(208, 17);
            this.chkNtGetContextThread.TabIndex = 4;
            this.chkNtGetContextThread.Text = "NtGetContextThread";
            this.chkNtGetContextThread.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtGetContextThread.UseVisualStyleBackColor = true;
            this.chkNtGetContextThread.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // groupBox5
            // 
            this.groupBox5.AutoSize = true;
            this.groupBox5.Controls.Add(this.chkNtQueryPerformanceCounter);
            this.groupBox5.Controls.Add(this.chkNtQuerySystemTime);
            this.groupBox5.Location = new System.Drawing.Point(261, 410);
            this.groupBox5.Name = "groupBox5";
            this.groupBox5.Size = new System.Drawing.Size(242, 105);
            this.groupBox5.TabIndex = 14;
            this.groupBox5.TabStop = false;
            this.groupBox5.Text = "Timing hooks";
            // 
            // chkNtQueryPerformanceCounter
            // 
            this.chkNtQueryPerformanceCounter.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtQueryPerformanceCounter.Location = new System.Drawing.Point(13, 42);
            this.chkNtQueryPerformanceCounter.Name = "chkNtQueryPerformanceCounter";
            this.chkNtQueryPerformanceCounter.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtQueryPerformanceCounter.Size = new System.Drawing.Size(208, 17);
            this.chkNtQueryPerformanceCounter.TabIndex = 15;
            this.chkNtQueryPerformanceCounter.Text = "NtQueryPerformanceCounter";
            this.chkNtQueryPerformanceCounter.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtQueryPerformanceCounter.UseVisualStyleBackColor = true;
            this.chkNtQueryPerformanceCounter.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // chkNtQuerySystemTime
            // 
            this.chkNtQuerySystemTime.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNtQuerySystemTime.Location = new System.Drawing.Point(13, 19);
            this.chkNtQuerySystemTime.Name = "chkNtQuerySystemTime";
            this.chkNtQuerySystemTime.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkNtQuerySystemTime.Size = new System.Drawing.Size(208, 17);
            this.chkNtQuerySystemTime.TabIndex = 13;
            this.chkNtQuerySystemTime.Text = "NtQuerySystemTime";
            this.chkNtQuerySystemTime.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkNtQuerySystemTime.UseVisualStyleBackColor = true;
            this.chkNtQuerySystemTime.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // btnSave
            // 
            this.btnSave.Location = new System.Drawing.Point(366, 783);
            this.btnSave.Name = "btnSave";
            this.btnSave.Size = new System.Drawing.Size(75, 23);
            this.btnSave.TabIndex = 4;
            this.btnSave.Text = "Save";
            this.btnSave.UseVisualStyleBackColor = true;
            this.btnSave.Click += new System.EventHandler(this.btnSave_Click);
            // 
            // btnClose
            // 
            this.btnClose.Location = new System.Drawing.Point(453, 783);
            this.btnClose.Name = "btnClose";
            this.btnClose.Size = new System.Drawing.Size(75, 23);
            this.btnClose.TabIndex = 5;
            this.btnClose.Text = "Close";
            this.btnClose.UseVisualStyleBackColor = true;
            this.btnClose.Click += new System.EventHandler(this.btnClose_Click);
            // 
            // chkBypassInstrumentationCallback
            // 
            this.chkBypassInstrumentationCallback.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkBypassInstrumentationCallback.Location = new System.Drawing.Point(13, 62);
            this.chkBypassInstrumentationCallback.Name = "chkBypassInstrumentationCallback";
            this.chkBypassInstrumentationCallback.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.chkBypassInstrumentationCallback.Size = new System.Drawing.Size(208, 17);
            this.chkBypassInstrumentationCallback.TabIndex = 23;
            this.chkBypassInstrumentationCallback.Text = "Bypass instrumentation callback *";
            this.chkBypassInstrumentationCallback.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.chkBypassInstrumentationCallback.UseVisualStyleBackColor = true;
            this.chkBypassInstrumentationCallback.CheckedChanged += new System.EventHandler(this.CheckBox_CheckedChanged);
            // 
            // EditForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(96F, 96F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            this.AutoSize = true;
            this.ClientSize = new System.Drawing.Size(539, 818);
            this.Controls.Add(this.btnClose);
            this.Controls.Add(this.btnSave);
            this.Controls.Add(this.groupBox3);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.groupBox1);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedToolWindow;
            this.Name = "EditForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Edit process rules";
            this.groupBox1.ResumeLayout(false);
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.groupBox3.ResumeLayout(false);
            this.groupBox3.PerformLayout();
            this.groupBox9.ResumeLayout(false);
            this.groupBox8.ResumeLayout(false);
            this.groupBox7.ResumeLayout(false);
            this.groupBox6.ResumeLayout(false);
            this.groupBox4.ResumeLayout(false);
            this.groupBox5.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ComboBox comboBoxProfiles;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.Button btnDeleteProfile;
        private System.Windows.Forms.Button btnAddProfile;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.CheckBox chkHideFromDebugger;
        private System.Windows.Forms.CheckBox chkMonitor;
        private System.Windows.Forms.CheckBox chkProtect;
        private System.Windows.Forms.GroupBox groupBox3;
        private System.Windows.Forms.CheckBox chkNtQuerySystemInformation;
        private System.Windows.Forms.CheckBox chkSpoofCodeIntegrity;
        private System.Windows.Forms.GroupBox groupBox4;
        private System.Windows.Forms.CheckBox chkKiDispatchException;
        private System.Windows.Forms.CheckBox chkNtContinue;
        private System.Windows.Forms.CheckBox chkNtSetContextThread;
        private System.Windows.Forms.CheckBox chkNtGetContextThread;
        private System.Windows.Forms.CheckBox chkNtSetInformationThread;
        private System.Windows.Forms.CheckBox chkNtQueryInformationProcess;
        private System.Windows.Forms.CheckBox chkNtQueryInformationThread;
        private System.Windows.Forms.CheckBox chkNtSetInformationProcess;
        private System.Windows.Forms.CheckBox chkNtQueryInformationJobObject;
        private System.Windows.Forms.CheckBox chkNtQueryObject;
        private System.Windows.Forms.CheckBox chkNtYieldExecution;
        private System.Windows.Forms.GroupBox groupBox5;
        private System.Windows.Forms.CheckBox chkNtQueryPerformanceCounter;
        private System.Windows.Forms.GroupBox groupBox6;
        private System.Windows.Forms.GroupBox groupBox8;
        private System.Windows.Forms.GroupBox groupBox7;
        private System.Windows.Forms.CheckBox chkBypassProcessFreeze;
        private System.Windows.Forms.CheckBox chkHidePEBBeingDebugged;
        private System.Windows.Forms.CheckBox chkHidePEBNtGlobalFlag;
        private System.Windows.Forms.CheckBox chkHidePEBHeapFlags;
        private System.Windows.Forms.CheckBox chkHideKUserSharedData;
        private System.Windows.Forms.CheckBox chkBypassProcessBreakOnTermination;
        private System.Windows.Forms.CheckBox chkBypassThreadBreakOnTermination;
        private System.Windows.Forms.CheckBox chkNtCreateThreadEx;
        private System.Windows.Forms.CheckBox chkNtClose;
        private System.Windows.Forms.CheckBox chkHideChildFromDebugger;
        private System.Windows.Forms.CheckBox chkSaveHandleTracingFlags;
        private System.Windows.Forms.CheckBox chkSaveDebugFlags;
        private System.Windows.Forms.CheckBox chkNtGetNextProcess;
        private System.Windows.Forms.CheckBox chkNtCreateUserProcess;
        private System.Windows.Forms.GroupBox groupBox9;
        private System.Windows.Forms.CheckBox chkNtUserQueryWindow;
        private System.Windows.Forms.CheckBox chkNtUserWindowFromPoint;
        private System.Windows.Forms.CheckBox chkNtUserGetForegroundWindow;
        private System.Windows.Forms.CheckBox chkNtUserFindWindowEx;
        private System.Windows.Forms.CheckBox chkNtUserBuildHwndList;
        private System.Windows.Forms.CheckBox chkNtSystemDebugControl;
        private System.Windows.Forms.Button btnSave;
        private System.Windows.Forms.Button btnClose;
        private System.Windows.Forms.CheckBox chkNtQuerySystemTime;
        private System.Windows.Forms.CheckBox chkBypassInstrumentationCallback;
    }
}