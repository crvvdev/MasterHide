
namespace MasterHideGUI
{
    partial class MainForm
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
            this.groupBoxProcessCfg = new System.Windows.Forms.GroupBox();
            this.btnApply = new System.Windows.Forms.Button();
            this.btnRemoveItem = new System.Windows.Forms.Button();
            this.btnEditItem = new System.Windows.Forms.Button();
            this.btnAddItem = new System.Windows.Forms.Button();
            this.listViewItems = new System.Windows.Forms.ListView();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.helpToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.installDriverToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.reinstallDriverToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.startDriverToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.restartDriverToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.stopDriverToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.checkDriverToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.groupBoxProcessCfg.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBoxProcessCfg
            // 
            this.groupBoxProcessCfg.AutoSize = true;
            this.groupBoxProcessCfg.Controls.Add(this.btnApply);
            this.groupBoxProcessCfg.Controls.Add(this.btnRemoveItem);
            this.groupBoxProcessCfg.Controls.Add(this.btnEditItem);
            this.groupBoxProcessCfg.Controls.Add(this.btnAddItem);
            this.groupBoxProcessCfg.Controls.Add(this.listViewItems);
            this.groupBoxProcessCfg.Location = new System.Drawing.Point(12, 27);
            this.groupBoxProcessCfg.Name = "groupBoxProcessCfg";
            this.groupBoxProcessCfg.Size = new System.Drawing.Size(541, 193);
            this.groupBoxProcessCfg.TabIndex = 0;
            this.groupBoxProcessCfg.TabStop = false;
            this.groupBoxProcessCfg.Text = "Process rules";
            // 
            // btnApply
            // 
            this.btnApply.Enabled = false;
            this.btnApply.Location = new System.Drawing.Point(446, 151);
            this.btnApply.Name = "btnApply";
            this.btnApply.Size = new System.Drawing.Size(75, 23);
            this.btnApply.TabIndex = 4;
            this.btnApply.Text = "Apply";
            this.btnApply.UseVisualStyleBackColor = true;
            this.btnApply.Click += new System.EventHandler(this.btnApply_Click);
            // 
            // btnRemoveItem
            // 
            this.btnRemoveItem.Enabled = false;
            this.btnRemoveItem.Location = new System.Drawing.Point(446, 77);
            this.btnRemoveItem.Name = "btnRemoveItem";
            this.btnRemoveItem.Size = new System.Drawing.Size(75, 23);
            this.btnRemoveItem.TabIndex = 3;
            this.btnRemoveItem.Text = "Remove";
            this.btnRemoveItem.UseVisualStyleBackColor = true;
            this.btnRemoveItem.Click += new System.EventHandler(this.btnRemoveItem_Click);
            // 
            // btnEditItem
            // 
            this.btnEditItem.Enabled = false;
            this.btnEditItem.Location = new System.Drawing.Point(446, 48);
            this.btnEditItem.Name = "btnEditItem";
            this.btnEditItem.Size = new System.Drawing.Size(75, 23);
            this.btnEditItem.TabIndex = 2;
            this.btnEditItem.Text = "Edit";
            this.btnEditItem.UseVisualStyleBackColor = true;
            this.btnEditItem.Click += new System.EventHandler(this.btnEditItem_Click);
            // 
            // btnAddItem
            // 
            this.btnAddItem.Location = new System.Drawing.Point(446, 19);
            this.btnAddItem.Name = "btnAddItem";
            this.btnAddItem.Size = new System.Drawing.Size(75, 23);
            this.btnAddItem.TabIndex = 1;
            this.btnAddItem.Text = "Add";
            this.btnAddItem.UseVisualStyleBackColor = true;
            this.btnAddItem.Click += new System.EventHandler(this.btnAddItem_Click);
            // 
            // listViewItems
            // 
            this.listViewItems.GridLines = true;
            this.listViewItems.HideSelection = false;
            this.listViewItems.Location = new System.Drawing.Point(17, 19);
            this.listViewItems.MultiSelect = false;
            this.listViewItems.Name = "listViewItems";
            this.listViewItems.Size = new System.Drawing.Size(423, 155);
            this.listViewItems.Sorting = System.Windows.Forms.SortOrder.Ascending;
            this.listViewItems.TabIndex = 0;
            this.listViewItems.UseCompatibleStateImageBehavior = false;
            this.listViewItems.View = System.Windows.Forms.View.List;
            this.listViewItems.SelectedIndexChanged += new System.EventHandler(this.ListViewItems_SelectedIndexChanged);
            // 
            // menuStrip1
            // 
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.helpToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(567, 24);
            this.menuStrip1.TabIndex = 1;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // helpToolStripMenuItem
            // 
            this.helpToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.installDriverToolStripMenuItem,
            this.reinstallDriverToolStripMenuItem,
            this.startDriverToolStripMenuItem,
            this.restartDriverToolStripMenuItem,
            this.stopDriverToolStripMenuItem,
            this.checkDriverToolStripMenuItem,
            this.aboutToolStripMenuItem});
            this.helpToolStripMenuItem.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.helpToolStripMenuItem.Name = "helpToolStripMenuItem";
            this.helpToolStripMenuItem.Size = new System.Drawing.Size(44, 20);
            this.helpToolStripMenuItem.Text = "Help";
            this.helpToolStripMenuItem.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.helpToolStripMenuItem.Click += new System.EventHandler(this.helpToolStripMenuItem_Click);
            // 
            // installDriverToolStripMenuItem
            // 
            this.installDriverToolStripMenuItem.Name = "installDriverToolStripMenuItem";
            this.installDriverToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.installDriverToolStripMenuItem.Text = "Install Driver";
            this.installDriverToolStripMenuItem.Click += new System.EventHandler(this.installDriverToolStripMenuItem_Click);
            // 
            // reinstallDriverToolStripMenuItem
            // 
            this.reinstallDriverToolStripMenuItem.Enabled = false;
            this.reinstallDriverToolStripMenuItem.Name = "reinstallDriverToolStripMenuItem";
            this.reinstallDriverToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.reinstallDriverToolStripMenuItem.Text = "Reinstall Driver";
            this.reinstallDriverToolStripMenuItem.Click += new System.EventHandler(this.reinstallDriverToolStripMenuItem_Click);
            // 
            // startDriverToolStripMenuItem
            // 
            this.startDriverToolStripMenuItem.Enabled = false;
            this.startDriverToolStripMenuItem.Name = "startDriverToolStripMenuItem";
            this.startDriverToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.startDriverToolStripMenuItem.Text = "Start Driver";
            this.startDriverToolStripMenuItem.Click += new System.EventHandler(this.startDriverToolStripMenuItem_Click);
            // 
            // restartDriverToolStripMenuItem
            // 
            this.restartDriverToolStripMenuItem.Enabled = false;
            this.restartDriverToolStripMenuItem.Name = "restartDriverToolStripMenuItem";
            this.restartDriverToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.restartDriverToolStripMenuItem.Text = "Restart Driver";
            this.restartDriverToolStripMenuItem.Click += new System.EventHandler(this.restartDriverToolStripMenuItem_Click);
            // 
            // stopDriverToolStripMenuItem
            // 
            this.stopDriverToolStripMenuItem.Enabled = false;
            this.stopDriverToolStripMenuItem.Name = "stopDriverToolStripMenuItem";
            this.stopDriverToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.stopDriverToolStripMenuItem.Text = "Stop Driver";
            this.stopDriverToolStripMenuItem.Click += new System.EventHandler(this.stopDriverToolStripMenuItem_Click);
            // 
            // checkDriverToolStripMenuItem
            // 
            this.checkDriverToolStripMenuItem.Name = "checkDriverToolStripMenuItem";
            this.checkDriverToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.checkDriverToolStripMenuItem.Text = "Check Driver";
            this.checkDriverToolStripMenuItem.Click += new System.EventHandler(this.checkDriverToolStripMenuItem_Click);
            // 
            // aboutToolStripMenuItem
            // 
            this.aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            this.aboutToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.aboutToolStripMenuItem.Text = "About";
            this.aboutToolStripMenuItem.Click += new System.EventHandler(this.aboutToolStripMenuItem_Click);
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(567, 232);
            this.Controls.Add(this.groupBoxProcessCfg);
            this.Controls.Add(this.menuStrip1);
            this.MainMenuStrip = this.menuStrip1;
            this.Name = "MainForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "MasterHide GUI";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.MainForm_FormClosed);
            this.groupBoxProcessCfg.ResumeLayout(false);
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBoxProcessCfg;
        private System.Windows.Forms.Button btnRemoveItem;
        private System.Windows.Forms.Button btnEditItem;
        private System.Windows.Forms.Button btnAddItem;
        private System.Windows.Forms.ListView listViewItems;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem helpToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem;
        private System.Windows.Forms.Button btnApply;
        private System.Windows.Forms.ToolStripMenuItem checkDriverToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem installDriverToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem reinstallDriverToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem startDriverToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem stopDriverToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem restartDriverToolStripMenuItem;
    }
}

