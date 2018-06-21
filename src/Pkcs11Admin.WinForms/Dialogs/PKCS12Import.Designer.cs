namespace Net.Pkcs11Admin.WinForms.Dialogs
{
    partial class PKCS12ImportDialog
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
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
            this.PKCS12OKButton = new System.Windows.Forms.Button();
            this.PKCS12CancelButton = new System.Windows.Forms.Button();
            this.PKCS12FilenameLabel = new System.Windows.Forms.Label();
            this.PKCS12FriendlyNameLabel = new System.Windows.Forms.Label();
            this.PKCS12BrowseButton = new System.Windows.Forms.Button();
            this.PKCS12FilenameTextBox = new System.Windows.Forms.TextBox();
            this.PKCS12FriendlyNameTextBox = new System.Windows.Forms.TextBox();
            this.PKCS12PasswordLabel = new System.Windows.Forms.Label();
            this.PKCS12PasswordTextBox = new System.Windows.Forms.TextBox();
            this.PKCS12ImportPublicKeyCheckBox = new System.Windows.Forms.CheckBox();
            this.PKCS12_CKA_ID_Label = new System.Windows.Forms.Label();
            this.PKCS12_CKA_ID_GenerationMethodComboBox = new System.Windows.Forms.ComboBox();
            this.SuspendLayout();
            // 
            // PKCS12OKButton
            // 
            this.PKCS12OKButton.Enabled = false;
            this.PKCS12OKButton.Location = new System.Drawing.Point(266, 321);
            this.PKCS12OKButton.Name = "PKCS12OKButton";
            this.PKCS12OKButton.Size = new System.Drawing.Size(75, 23);
            this.PKCS12OKButton.TabIndex = 8;
            this.PKCS12OKButton.Text = "OK";
            this.PKCS12OKButton.UseVisualStyleBackColor = true;
            this.PKCS12OKButton.Click += new System.EventHandler(this.PKCS12OKButton_Click);
            // 
            // PKCS12CancelButton
            // 
            this.PKCS12CancelButton.Location = new System.Drawing.Point(348, 321);
            this.PKCS12CancelButton.Name = "PKCS12CancelButton";
            this.PKCS12CancelButton.Size = new System.Drawing.Size(75, 23);
            this.PKCS12CancelButton.TabIndex = 9;
            this.PKCS12CancelButton.Text = "Cancel";
            this.PKCS12CancelButton.UseVisualStyleBackColor = true;
            this.PKCS12CancelButton.Click += new System.EventHandler(this.PKCS12CancelButton_Click);
            // 
            // PKCS12FilenameLabel
            // 
            this.PKCS12FilenameLabel.AutoSize = true;
            this.PKCS12FilenameLabel.Location = new System.Drawing.Point(13, 23);
            this.PKCS12FilenameLabel.Name = "PKCS12FilenameLabel";
            this.PKCS12FilenameLabel.Size = new System.Drawing.Size(120, 13);
            this.PKCS12FilenameLabel.TabIndex = 0;
            this.PKCS12FilenameLabel.Text = "PKCS#12 File to Import:";
            // 
            // PKCS12FriendlyNameLabel
            // 
            this.PKCS12FriendlyNameLabel.AutoSize = true;
            this.PKCS12FriendlyNameLabel.Location = new System.Drawing.Point(13, 215);
            this.PKCS12FriendlyNameLabel.Name = "PKCS12FriendlyNameLabel";
            this.PKCS12FriendlyNameLabel.Size = new System.Drawing.Size(170, 13);
            this.PKCS12FriendlyNameLabel.TabIndex = 5;
            this.PKCS12FriendlyNameLabel.Text = "PKCS#12 FriendlyName (optional):";
            // 
            // PKCS12BrowseButton
            // 
            this.PKCS12BrowseButton.Location = new System.Drawing.Point(347, 49);
            this.PKCS12BrowseButton.Name = "PKCS12BrowseButton";
            this.PKCS12BrowseButton.Size = new System.Drawing.Size(75, 23);
            this.PKCS12BrowseButton.TabIndex = 2;
            this.PKCS12BrowseButton.Text = "Browse";
            this.PKCS12BrowseButton.UseVisualStyleBackColor = true;
            this.PKCS12BrowseButton.Click += new System.EventHandler(this.PKCS12BrowseButton_Click);
            // 
            // PKCS12FilenameTextBox
            // 
            this.PKCS12FilenameTextBox.Location = new System.Drawing.Point(16, 49);
            this.PKCS12FilenameTextBox.Name = "PKCS12FilenameTextBox";
            this.PKCS12FilenameTextBox.Size = new System.Drawing.Size(325, 20);
            this.PKCS12FilenameTextBox.TabIndex = 1;
            this.PKCS12FilenameTextBox.TextChanged += new System.EventHandler(this.PKCS12FilenameTextBox_TextChanged);
            // 
            // PKCS12FriendlyNameTextBox
            // 
            this.PKCS12FriendlyNameTextBox.Location = new System.Drawing.Point(16, 244);
            this.PKCS12FriendlyNameTextBox.Name = "PKCS12FriendlyNameTextBox";
            this.PKCS12FriendlyNameTextBox.Size = new System.Drawing.Size(325, 20);
            this.PKCS12FriendlyNameTextBox.TabIndex = 6;
            // 
            // PKCS12PasswordLabel
            // 
            this.PKCS12PasswordLabel.AutoSize = true;
            this.PKCS12PasswordLabel.Location = new System.Drawing.Point(13, 84);
            this.PKCS12PasswordLabel.Name = "PKCS12PasswordLabel";
            this.PKCS12PasswordLabel.Size = new System.Drawing.Size(106, 13);
            this.PKCS12PasswordLabel.TabIndex = 3;
            this.PKCS12PasswordLabel.Text = "PKCS#12 Password:";
            // 
            // PKCS12PasswordTextBox
            // 
            this.PKCS12PasswordTextBox.Location = new System.Drawing.Point(16, 110);
            this.PKCS12PasswordTextBox.Name = "PKCS12PasswordTextBox";
            this.PKCS12PasswordTextBox.Size = new System.Drawing.Size(325, 20);
            this.PKCS12PasswordTextBox.TabIndex = 4;
            this.PKCS12PasswordTextBox.UseSystemPasswordChar = true;
            this.PKCS12PasswordTextBox.TextChanged += new System.EventHandler(this.PKCS12PasswordTextBox_TextChanged);
            // 
            // PKCS12ImportPublicKeyCheckBox
            // 
            this.PKCS12ImportPublicKeyCheckBox.AutoSize = true;
            this.PKCS12ImportPublicKeyCheckBox.Location = new System.Drawing.Point(16, 289);
            this.PKCS12ImportPublicKeyCheckBox.Name = "PKCS12ImportPublicKeyCheckBox";
            this.PKCS12ImportPublicKeyCheckBox.Size = new System.Drawing.Size(108, 17);
            this.PKCS12ImportPublicKeyCheckBox.TabIndex = 7;
            this.PKCS12ImportPublicKeyCheckBox.Text = "Import Public Key";
            this.PKCS12ImportPublicKeyCheckBox.UseVisualStyleBackColor = true;
            // 
            // PKCS12_CKA_ID_Label
            // 
            this.PKCS12_CKA_ID_Label.AutoSize = true;
            this.PKCS12_CKA_ID_Label.Location = new System.Drawing.Point(13, 147);
            this.PKCS12_CKA_ID_Label.Name = "PKCS12_CKA_ID_Label";
            this.PKCS12_CKA_ID_Label.Size = new System.Drawing.Size(142, 13);
            this.PKCS12_CKA_ID_Label.TabIndex = 10;
            this.PKCS12_CKA_ID_Label.Text = "CKA_ID Generation Method:";
            // 
            // PKCS12_CKA_ID_GenerationMethodComboBox
            // 
            this.PKCS12_CKA_ID_GenerationMethodComboBox.FormattingEnabled = true;
            this.PKCS12_CKA_ID_GenerationMethodComboBox.Items.AddRange(new object[] {
            "Default (PKCS#11 Recommendation - SHA1 hash of subjectKeyIdentifier)",
            "Mozilla Compatible CKA_ID (SHA1 hash of modulus)"});
            this.PKCS12_CKA_ID_GenerationMethodComboBox.Location = new System.Drawing.Point(16, 177);
            this.PKCS12_CKA_ID_GenerationMethodComboBox.Name = "PKCS12_CKA_ID_GenerationMethodComboBox";
            this.PKCS12_CKA_ID_GenerationMethodComboBox.Size = new System.Drawing.Size(369, 21);
            this.PKCS12_CKA_ID_GenerationMethodComboBox.TabIndex = 11;
            // 
            // PKCS12ImportDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(435, 357);
            this.Controls.Add(this.PKCS12_CKA_ID_GenerationMethodComboBox);
            this.Controls.Add(this.PKCS12_CKA_ID_Label);
            this.Controls.Add(this.PKCS12ImportPublicKeyCheckBox);
            this.Controls.Add(this.PKCS12PasswordTextBox);
            this.Controls.Add(this.PKCS12PasswordLabel);
            this.Controls.Add(this.PKCS12FriendlyNameTextBox);
            this.Controls.Add(this.PKCS12FilenameTextBox);
            this.Controls.Add(this.PKCS12BrowseButton);
            this.Controls.Add(this.PKCS12FriendlyNameLabel);
            this.Controls.Add(this.PKCS12FilenameLabel);
            this.Controls.Add(this.PKCS12CancelButton);
            this.Controls.Add(this.PKCS12OKButton);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "PKCS12ImportDialog";
            this.Padding = new System.Windows.Forms.Padding(9);
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "PKCS12Import";
            this.KeyDown += new System.Windows.Forms.KeyEventHandler(this.PKCS12ImportKeyDown);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button PKCS12OKButton;
        private System.Windows.Forms.Button PKCS12CancelButton;
        private System.Windows.Forms.Label PKCS12FilenameLabel;
        private System.Windows.Forms.Label PKCS12FriendlyNameLabel;
        private System.Windows.Forms.Button PKCS12BrowseButton;
        private System.Windows.Forms.TextBox PKCS12FilenameTextBox;
        private System.Windows.Forms.TextBox PKCS12FriendlyNameTextBox;
        private System.Windows.Forms.Label PKCS12PasswordLabel;
        private System.Windows.Forms.TextBox PKCS12PasswordTextBox;
        private System.Windows.Forms.CheckBox PKCS12ImportPublicKeyCheckBox;
        private System.Windows.Forms.Label PKCS12_CKA_ID_Label;
        private System.Windows.Forms.ComboBox PKCS12_CKA_ID_GenerationMethodComboBox;
    }
}
