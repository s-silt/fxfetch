using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

// .NET Framework launcher. All machine state lives outside the source package.
public static class Setup
{
    public static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    public static string Quote(string value)
    {
        if (value.IndexOf('\0') >= 0 || value.IndexOf('\r') >= 0 || value.IndexOf('\n') >= 0)
            throw new ArgumentException("invalid_argument");
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { slashes++; continue; }
            result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes);
            result.Append(c); slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }
    public static ProcessStartInfo ProcessInfo(string executable, string[] arguments, string directory)
    {
        var info = new ProcessStartInfo(executable, String.Join(" ", arguments.Select(Quote))) {
            WorkingDirectory = directory, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
            StandardOutputEncoding = Utf8, StandardErrorEncoding = Utf8
        };
        info.EnvironmentVariables["PYTHONUTF8"] = "1";
        info.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
        info.EnvironmentVariables.Remove("PYTHONPATH");
        info.EnvironmentVariables.Remove("PYTHONHOME");
        info.EnvironmentVariables.Remove("PSModulePath");
        return info;
    }
    [STAThread]
    public static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        bool created;
        using (var mutex = new System.Threading.Mutex(true, "Local\\fxfetch-offline-setup", out created))
        {
            if (!created) { MessageBox.Show("安装或启动窗口已经打开。", "fxfetch"); return; }
            Application.Run(new SetupForm(args.Contains("--launch") || Path.GetFileName(Application.ExecutablePath).Equals("fxfetch.exe", StringComparison.OrdinalIgnoreCase)));
        }
    }
}

public sealed class SetupForm : Form
{
    readonly string bundle = AppDomain.CurrentDomain.BaseDirectory;
    readonly bool launcher;
    readonly TextBox location = new TextBox();
    readonly ComboBox addresses = new ComboBox();
    readonly TextBox subnet = new TextBox();
    readonly TextBox password = new TextBox();
    readonly CheckBox defaultPassword = new CheckBox();
    readonly CheckBox terms = new CheckBox();
    readonly TextBox log = new TextBox();
    readonly Button start = new Button();
    readonly Button open = new Button();
    bool running;
    string verifiedUrl;
    public SetupForm(bool launch)
    {
        launcher = launch;
        Text = launch ? "fxfetch · 启动服务" : "fxfetch · 离线安装";
        Font = new Font("Microsoft YaHei UI", 10);
        ClientSize = new Size(720, 670); MinimumSize = new Size(700, 640);
        StartPosition = FormStartPosition.CenterScreen;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), ColumnCount = 1, RowCount = 11 };
        Controls.Add(layout);
        layout.Controls.Add(new Label { Text = launch ? "启动 Docker 服务并打开局域网页面" : "在这台电脑建立独立服务", AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
        layout.Controls.Add(new Label { Text = "Windows 11 x64 · Intel / AMD · 硬件虚拟化 · 建议 16 GB 内存、60 GB 可用空间", AutoSize = true });
        var pathRow = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 2, RowCount = 1 };
        pathRow.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
        location.Text = launch || File.Exists(Path.Combine(bundle, "private", "installation.json"))
            ? bundle.TrimEnd('\\') : Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "fxfetch");
        location.Dock = DockStyle.Fill;
        var browse = new Button { Text = "安装目录", Anchor = AnchorStyles.Top | AnchorStyles.Left, AutoSize = true };
        browse.Click += delegate { using (var dialog = new FolderBrowserDialog()) { if (dialog.ShowDialog() == DialogResult.OK) location.Text = dialog.SelectedPath; } };
        pathRow.Controls.Add(location); pathRow.Controls.Add(browse); layout.Controls.Add(pathRow);
        var networkRow = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        networkRow.Controls.Add(new Label { Text = "局域网地址", AutoSize = true, Padding = new Padding(0, 5, 0, 0) });
        addresses.DropDownStyle = ComboBoxStyle.DropDownList; addresses.Width = 180;
        var networks = new Dictionary<string, string>();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces().Where(a => a.OperationalStatus == OperationalStatus.Up)
            .OrderByDescending(a => a.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(System.Net.IPAddress.Any))))
            foreach (var ip in adapter.GetIPProperties().UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork))
            {
                byte[] b = ip.Address.GetAddressBytes();
                if (!(b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 || b[0] == 192 && b[1] == 168)) continue;
                byte[] m = ip.IPv4Mask.GetAddressBytes(); int bits = m.Sum(x => Convert.ToString(x, 2).Count(c => c == '1'));
                string net = String.Join(".", b.Select((v, i) => (v & m[i]).ToString())) + "/" + bits;
                networks[ip.Address.ToString()] = net;
            }
        foreach (string address in networks.Keys) addresses.Items.Add(address);
        addresses.SelectedIndexChanged += delegate { subnet.Text = networks[(string)addresses.SelectedItem]; };
        if (addresses.Items.Count > 0) addresses.SelectedIndex = 0;
        networkRow.Controls.Add(addresses); networkRow.Controls.Add(new Label { Text = "允许网段", AutoSize = true, Padding = new Padding(6, 5, 0, 0) });
        subnet.Width = 185; networkRow.Controls.Add(subnet); layout.Controls.Add(networkRow);
        defaultPassword.Text = "使用随安装包预置的默认口令"; defaultPassword.AutoSize = true;
        defaultPassword.Checked = File.Exists(Path.Combine(bundle, "defaults.json"));
        layout.Controls.Add(defaultPassword);
        password.UseSystemPasswordChar = true; password.Enabled = !defaultPassword.Checked; password.Width = 340;
        defaultPassword.CheckedChanged += delegate { password.Enabled = !defaultPassword.Checked; };
        var passRow = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        passRow.Controls.Add(new Label { Text = "自定义口令（至少 12 位）", AutoSize = true, Padding = new Padding(0, 5, 0, 0) }); passRow.Controls.Add(password); layout.Controls.Add(passRow);
        terms.Text = "我已阅读并同意 Docker Desktop 条款及所附第三方许可"; terms.AutoSize = true;
        layout.Controls.Add(terms);
        var license = new LinkLabel { Text = "离线查看 Docker 许可协议", AutoSize = true };
        license.LinkClicked += delegate {
            string file = Path.Combine(bundle, "assets", "licenses", "Docker-LICENSE.rtf");
            if (!File.Exists(file)) { Append("缺少随包许可，请使用完整安装包。"); return; }
            using (var dialog = new Form { Text = "Docker Desktop 许可协议", ClientSize = new Size(820, 650), StartPosition = FormStartPosition.CenterParent })
            using (var content = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, DetectUrls = false })
            { content.LoadFile(file, RichTextBoxStreamType.RichText); dialog.Controls.Add(content); dialog.ShowDialog(this); }
        };
        layout.Controls.Add(license);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        start.Text = launch ? "启动服务" : "开始安装 / 继续安装"; start.AutoSize = true; start.Click += async delegate { await Run(); };
        open.Text = "打开网页"; open.AutoSize = true; open.Enabled = false;
        open.Click += delegate { OpenWebsite(); }; buttons.Controls.Add(start); buttons.Controls.Add(open); layout.Controls.Add(buttons);
        log.Multiline = true; log.ReadOnly = true; log.ScrollBars = ScrollBars.Vertical; log.Dock = DockStyle.Fill;
        layout.Controls.Add(log); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        for (int i = 1; i < 9; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = "安装期间不访问目标网站。关闭启动器不会停止已运行的 Docker 服务。", AutoSize = true });
        FormClosing += delegate(object sender, FormClosingEventArgs e) { if (running) { e.Cancel = true; Append("正在安装，请等待当前步骤结束；不会强制重启电脑。"); } };
        if (launch) { browse.Enabled = location.Enabled = addresses.Enabled = subnet.Enabled = terms.Enabled = defaultPassword.Enabled = password.Enabled = false; Shown += async delegate { await Run(); }; }
    }
    void Append(string message)
    {
        if (InvokeRequired) { BeginInvoke(new Action<string>(Append), message); return; }
        if (log.TextLength > 24000) log.Text = log.Text.Substring(log.TextLength - 16000);
        log.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + message + Environment.NewLine);
    }
    void OpenWebsite()
    {
        if (verifiedUrl == null) return;
        try { Process.Start(new ProcessStartInfo(verifiedUrl) { UseShellExecute = true }); }
        catch (System.ComponentModel.Win32Exception) { Append("浏览器未能打开，请复制地址访问：" + verifiedUrl); }
    }
    static string PhaseMessage(Dictionary<string, object> row)
    {
        string phase = row.ContainsKey("phase") ? Convert.ToString(row["phase"]) : "";
        switch (phase)
        {
            case "existing_owned_guest_reused": return "复用本机已有的独立 Android 环境。";
            case "owned_partial_prepare_resumed": return "恢复上次中断的环境准备。";
            case "fresh_guest_disk_copy_started": return "正在复制干净软件模板，不需要下载。";
            case "guest_cloud_init_completed": return "本机独立身份和初始配置已完成。";
            case "guest_first_boot_ready": return "虚拟环境已启动，正在初始化浏览器。";
            case "guest_payload_copied": return "已传入一项预置组件。";
            case "guest_offline_baseline_completed": return "离线浏览器和磁盘限额检查完成。";
            case "guest_synthetic_gate_started":
            case "guest_synthetic_gate_passed":
                string gate = row.ContainsKey("gate") ? Convert.ToString(row["gate"]) : "";
                string title = gate == "android_browser_acceptance.py" ? "自动下载" : gate == "android_lease_acceptance.py" ? "网络隔离与取消" : "任务超时";
                return title + (phase.EndsWith("passed") ? "验收通过。" : "验收进行中，请稍候……");
        }
        if (row.ContainsKey("state") && Convert.ToString(row["state"]) == "synthetic_acceptance_passed")
            return "Android 验收通过，继续配置网页服务。";
        return null;
    }
    async Task Run()
    {
        if (running) return;
        if (!launcher && (!terms.Checked || addresses.SelectedItem == null)) { Append("请选择本机局域网地址，并阅读、接受所附许可。"); return; }
        if (!launcher && !defaultPassword.Checked && password.Text.Length < 12) { Append("自定义口令至少需要 12 位。"); return; }
        running = true; start.Enabled = open.Enabled = false; verifiedUrl = null;
        try
        {
            string root = Path.GetFullPath(location.Text);
            string python = Path.Combine(bundle, "runtime", "python.exe");
            string script = Path.Combine(bundle, "app", "scripts", "windows-installer", "install.py");
            if (!File.Exists(python) || !File.Exists(script)) throw new IOException("安装包不完整，请完整解压后运行。");
            var args = new List<string> { "-X", "utf8", "-u", script, launcher ? "launch" : "install", "--root", root, "--bundle", bundle };
            if (!launcher) args.AddRange(new[] { "--lan-ip", (string)addresses.SelectedItem, "--subnet", subnet.Text, "--accept-licenses" });
            var json = new JavaScriptSerializer();
            string secret = json.Serialize(new { use_default = defaultPassword.Checked, password = defaultPassword.Checked ? "" : password.Text });
            password.Clear();
            await Task.Run(async delegate {
                using (var child = new Process { StartInfo = Setup.ProcessInfo(python, args.ToArray(), bundle) })
                {
                    child.Start();
                    using (var input = new StreamWriter(child.StandardInput.BaseStream, Setup.Utf8)) { input.WriteLine(secret); }
                    secret = null;
                    // Drain both streams concurrently. Only structured, bounded status is displayed.
                    var errTask = DrainErrors(child.StandardError);
                    string line;
                    while ((line = await child.StandardOutput.ReadLineAsync()) != null)
                    {
                        if (line.Length > 16384) continue;
                        try
                        {
                            var row = json.Deserialize<Dictionary<string, object>>(line);
                            if (row.ContainsKey("message")) Append(Convert.ToString(row["message"]));
                            else { string phaseMessage = PhaseMessage(row); if (phaseMessage != null) Append(phaseMessage); }
                            if (row.ContainsKey("status") && Convert.ToString(row["status"]) == "ready" && row.ContainsKey("url"))
                            {
                                Uri url; byte[] bytes;
                                System.Net.IPAddress ip;
                                if (Uri.TryCreate(Convert.ToString(row["url"]), UriKind.Absolute, out url) && url.Scheme == "http" &&
                                    System.Net.IPAddress.TryParse(url.Host, out ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
                                    url.UserInfo == "" && url.AbsolutePath == "/" && url.Query == "" && url.Fragment == "" && url.Port >= 1024)
                                {
                                    bytes = ip.GetAddressBytes();
                                    if (bytes[0] == 10 || bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31 || bytes[0] == 192 && bytes[1] == 168)
                                        verifiedUrl = url.AbsoluteUri;
                                }
                            }
                        }
                        catch (ArgumentException) { Append("收到非预期状态，未将其作为成功。"); }
                        catch (InvalidOperationException) { Append("状态格式无效。"); }
                    }
                    await errTask; child.WaitForExit();
                    if (child.ExitCode != 0) { verifiedUrl = null; Append(child.ExitCode == 20 ? "需要重启 Windows。保存工作并手动重启，再运行安装程序继续。" : "本次未完成，请查看上方原因；现有数据不会被自动删除。"); }
                }
            });
            open.Enabled = verifiedUrl != null;
            if (verifiedUrl != null) { Append("服务已就绪：" + verifiedUrl); OpenWebsite(); }
        }
        catch (Exception error)
        {
            if (!(error is IOException || error is UnauthorizedAccessException || error is ArgumentException || error is System.ComponentModel.Win32Exception || error is System.Text.DecoderFallbackException)) throw;
            Append("无法完成本地启动或安装，请检查完整安装包、路径和权限。");
        }
        finally { running = false; start.Enabled = true; }
    }
    static async Task DrainErrors(StreamReader reader)
    {
        char[] buffer = new char[4096];
        while (await reader.ReadAsync(buffer, 0, buffer.Length) != 0) { /* Never expose credentials/tracebacks. */ }
    }
}
