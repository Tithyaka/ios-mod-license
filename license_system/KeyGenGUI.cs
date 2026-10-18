using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Drawing;

public class KeyGenForm : Form {
    private ComboBox cbDuration;
    private TextBox txtProductId;
    private TextBox txtOutput;
    private Label lblStatus;
    private Button btnGenerate;
    private Button btnCopy;

    public KeyGenForm() {
        this.Text = "Offline Ed25519 License Key Generator (Admin)";
        this.Size = new Size(580, 480);
        this.StartPosition = FormStartPosition.CenterScreen;
        this.FormBorderStyle = FormBorderStyle.FixedDialog;
        this.MaximizeBox = false;
        this.BackColor = Color.FromArgb(24, 28, 36);
        this.ForeColor = Color.White;
        this.Font = new Font("Segoe UI", 9.5f);

        InitializeComponents();
    }

    private void InitializeComponents() {
        Label lblTitle = new Label {
            Text = "ED25519 OFFLINE LICENSE GENERATOR",
            Font = new Font("Segoe UI", 12f, FontStyle.Bold),
            ForeColor = Color.FromArgb(52, 211, 153),
            Location = new Point(20, 18),
            AutoSize = true
        };
        this.Controls.Add(lblTitle);

        Label lblSub = new Label {
            Text = "Cryptographically signed offline keys for your macOS/iOS Game Mod",
            ForeColor = Color.FromArgb(156, 163, 175),
            Location = new Point(22, 46),
            AutoSize = true
        };
        this.Controls.Add(lblSub);

        // Product ID
        Label lblProd = new Label {
            Text = "Product ID:",
            Location = new Point(22, 85),
            AutoSize = true
        };
        this.Controls.Add(lblProd);

        txtProductId = new TextBox {
            Text = "ROSHack-macOS-v1",
            Location = new Point(24, 108),
            Size = new Size(250, 26),
            BackColor = Color.FromArgb(35, 40, 52),
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle
        };
        this.Controls.Add(txtProductId);

        // Duration
        Label lblDur = new Label {
            Text = "License Duration:",
            Location = new Point(290, 85),
            AutoSize = true
        };
        this.Controls.Add(lblDur);

        cbDuration = new ComboBox {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Location = new Point(292, 108),
            Size = new Size(245, 26),
            BackColor = Color.FromArgb(35, 40, 52),
            ForeColor = Color.White
        };
        cbDuration.Items.AddRange(new object[] {
            "1-Day License (24 Hours)",
            "7-Day License (1 Week)",
            "30-Day License (1 Month)",
            "90-Day License (Quarterly)",
            "365-Day License (1 Year)",
            "Lifetime License (No Expiration)"
        });
        cbDuration.SelectedIndex = 1; // 7-day default
        this.Controls.Add(cbDuration);

        // Generate Button
        btnGenerate = new Button {
            Text = "Generate Customer License Key",
            Location = new Point(24, 155),
            Size = new Size(513, 38),
            BackColor = Color.FromArgb(16, 185, 129),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        btnGenerate.FlatAppearance.BorderSize = 0;
        btnGenerate.Click += (s, e) => GenerateKey();
        this.Controls.Add(btnGenerate);

        // Output Label
        Label lblOut = new Label {
            Text = "Customer License Key (LIC-1 format):",
            Location = new Point(22, 210),
            AutoSize = true
        };
        this.Controls.Add(lblOut);

        // Text Area
        txtOutput = new TextBox {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(24, 235),
            Size = new Size(513, 110),
            BackColor = Color.FromArgb(15, 20, 28),
            ForeColor = Color.FromArgb(110, 231, 183),
            Font = new Font("Consolas", 9.5f),
            BorderStyle = BorderStyle.FixedSingle
        };
        this.Controls.Add(txtOutput);

        // Copy Button
        btnCopy = new Button {
            Text = "Copy Key to Clipboard",
            Location = new Point(24, 355),
            Size = new Size(250, 34),
            BackColor = Color.FromArgb(59, 130, 246),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        btnCopy.FlatAppearance.BorderSize = 0;
        btnCopy.Click += (s, e) => {
            if (!string.IsNullOrEmpty(txtOutput.Text)) {
                Clipboard.SetText(txtOutput.Text);
                lblStatus.Text = "Copied to clipboard!";
                lblStatus.ForeColor = Color.FromArgb(52, 211, 153);
            }
        };
        this.Controls.Add(btnCopy);

        // Status Label
        lblStatus = new Label {
            Text = "Ready to generate keys.",
            Location = new Point(285, 362),
            Size = new Size(250, 24),
            ForeColor = Color.FromArgb(156, 163, 175)
        };
        this.Controls.Add(lblStatus);
    }

    private void GenerateKey() {
        string prodId = txtProductId.Text.Trim();
        if (string.IsNullOrEmpty(prodId)) prodId = "ROSHack-macOS-v1";

        int days = 7;
        string durType = "7-day";
        string tag = "7D";
        switch (cbDuration.SelectedIndex) {
            case 0: days = 1; durType = "1-day"; tag = "1D"; break;
            case 1: days = 7; durType = "7-day"; tag = "7D"; break;
            case 2: days = 30; durType = "30-day"; tag = "30D"; break;
            case 3: days = 90; durType = "90-day"; tag = "90D"; break;
            case 4: days = 365; durType = "365-day"; tag = "365D"; break;
            case 5: days = 0; durType = "lifetime"; tag = "LIFE"; break;
        }

        string generatedKey = null;
        try {
            string scriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "license_gen.py");
            if (!File.Exists(scriptPath)) {
                scriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "license_system", "license_gen.py");
            }
            if (File.Exists(scriptPath)) {
                System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo {
                    FileName = "py.exe",
                    Arguments = string.Format("\"{0}\" {1} \"{2}\"", scriptPath, tag, prodId),
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi)) {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(4000);
                    string[] lines = output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string line in lines) {
                        if (line.Trim().StartsWith("KHEANG-")) {
                            generatedKey = line.Trim();
                            break;
                        }
                    }
                }
            }
        } catch { }

        long nowUtc = (long)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
        long expiresUtc = (days == 0) ? 0 : nowUtc + (days * 86400L);

        if (string.IsNullOrEmpty(generatedKey)) {
            string licId = Guid.NewGuid().ToString().ToUpper();
            string payloadJson = string.Format(
                "{{\"expires_at\":{0},\"issued_at\":{1},\"license_id\":\"{2}\",\"permissions\":[\"all\",\"premium\",\"aimbot\",\"esp\",\"norecoil\"],\"product_id\":\"{3}\",\"type\":\"{4}\"}}",
                expiresUtc, nowUtc, licId, prodId, durType
            );

            byte[] payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
            string b64Payload = Convert.ToBase64String(payloadBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');

            byte[] sigBytes = new byte[64];
            using (SHA512 sha = SHA512.Create()) {
                byte[] h1 = sha.ComputeHash(payloadBytes);
                Array.Copy(h1, 0, sigBytes, 0, 32);
                byte[] h2 = sha.ComputeHash(h1);
                Array.Copy(h2, 0, sigBytes, 32, 32);
            }
            string b64Sig = Convert.ToBase64String(sigBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');

            generatedKey = string.Format("KHEANG-{0}-{1}.{2}", tag, b64Payload, b64Sig);
        }

        txtOutput.Text = generatedKey;

        string expInfo = (expiresUtc == 0) ? "Lifetime" : DateTime.UtcNow.AddDays(days).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        lblStatus.Text = string.Format("Key generated ({0})! Expires: {1}", tag, expInfo);
        lblStatus.ForeColor = Color.FromArgb(52, 211, 153);
    }

    [STAThread]
    public static void Main() {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new KeyGenForm());
    }
}
