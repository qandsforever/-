using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using zlib;
namespace 网络抓包分析
{
    public partial class Form1 : Form
    {
        Dictionary<string, int> dicDVG = new Dictionary<string, int>();
        Dictionary<int, List<long>> datas = new Dictionary<int, List<long>>();
        Dictionary<int, ulong> dataLen = new Dictionary<int, ulong>();
        Dictionary<int, byte[]> udpData = new Dictionary<int, byte[]>();
        Dictionary<int, int> dataRST = new Dictionary<int, int>();
        Dictionary<int, DataRow> dicDataRows = new Dictionary<int, DataRow>();
        private object rowLock = new object();
        private delegate void DelegateDataGridViewAddRow();
        public IPSearch ipSearch=null;

        int comboindex = 0;
        public Form1()
        {
            InitializeComponent();
        }

        captureClass cp = new captureClass();

        
        

        private void Form1_Load(object sender, EventArgs e)
        {
            this.Icon = Properties.Resources.ConfigureWERTask;

            dataGridView1.Columns[6].ToolTipText = "响应时长\r\n(最大/最小/平均)";

            dataGridView1.Size = new Size(this.Size.Width - 20, this.Size.Height - 90);
            foreach(DataGridViewColumn col in dataGridView1.Columns)
            {
               col.SortMode = System.Windows.Forms.DataGridViewColumnSortMode.NotSortable;
            }
            

            comboBox1.SelectedIndex = 0;
           
            //进程捕获
            Task taskGetNetProcess = new Task(() => {

                while (true)
                {
                    try
                    {
                       
                        NetProcessAPI.updateNetProcessInfo();
                        

                    }
                    catch
                    {

                    }

                    Thread.Sleep(50);
                }
            });
            taskGetNetProcess.Start();

            //开始抓包
            try
            {
                cp.startCatch();
            }
            catch
            {
                MessageBox.Show("请先安装npcap-0.9997(win7以上)或WinPcap_4_1_3后再运行程序");
                System.Environment.Exit(0);
            }

            //读IP库
         
            


            ulong tcpDataLen = 0;
            ulong udpDataLen = 0;

            Task catureTask = new Task(() => {
                List<PacketClass> packets = new List<PacketClass>();
                while (true)
                {
                    try
                    {
                       
                        packets = packets.Union(cp.getPackets()).ToList();
                        var ap = cp.AnalyePacket(packets, tcpDataLen, udpDataLen);
                        packets = ap.packets;
                        tcpDataLen = ap.TcpdataLen;
                        udpDataLen = ap.UdpdataLen;


                        for (int i = 0; i < ap.packetStatistics.Count; i++)
                        {
                            if (!cp.srcIPList.Contains(ap.packetStatistics[i].srcIP))
                            {
                                string dstIP = ap.packetStatistics[i].srcIP;
                                string dstPort = ap.packetStatistics[i].sourcePort;
                                ap.packetStatistics[i].srcIP = ap.packetStatistics[i].destIP;
                                ap.packetStatistics[i].sourcePort = ap.packetStatistics[i].destPort;
                                ap.packetStatistics[i].destIP = dstIP;
                                ap.packetStatistics[i].destPort = dstPort;
                            }
                        }

                        

                        changeDGVdata(ap.packetStatistics);
                     
                    }
                    catch 
                    {

                    }


                    Thread.Sleep(1000);

                }

            });

            catureTask.Start();

            timer1.Enabled = true;
            timer2.Enabled = true;
            Thread.Sleep(1000);
            new Task(() => { ipSearch = getIpDataClass.checkUpdate(); }).Start();

        }


        private void changeDGVdata(List<PacketStatistics> packets)
        {
            foreach (PacketStatistics packet in packets)
            {
                string src = packet.srcIP;
                string dst = packet.destIP + ":" + packet.destPort;

                if (dicDVG.ContainsKey(src + "-" + dst))
                {
                    var data = datas[dicDVG[src + "-" + dst]];
                    if (data.Count >= 0)
                    {
                        data.Add(packet.answerTime);
                        datas[dicDVG[src + "-" + dst]] = data;
                        dataLen[dicDVG[src + "-" + dst]] += packet.PacketLength;
                        if (packet.isRST)
                        {
                            dataRST[dicDVG[src + "-" + dst]] += 1;
                        }
                        if (packet.udpPacketContent != null)
                        {
                            udpData[dicDVG[src + "-" + dst]] = packet.udpPacketContent;
                        }
                    }

                }
                else
                {

                    dicDVG.Add(src + "-" + dst, dataGridView1.Rows.Count);
                    List<long> data = new List<long>();
                    data.Add(packet.answerTime);
                    datas.Add(dataGridView1.Rows.Count, data);
                    dataLen.Add(dataGridView1.Rows.Count, packet.PacketLength);
                    dataRST.Add(dataGridView1.Rows.Count, packet.isRST ? 1 : 0);
                    udpData.Add(dataGridView1.Rows.Count, packet.udpPacketContent);
                    string key = "";
                    if (packet.protocol == "TCP")
                    {
                        key = packet.srcIP + "-" + packet.destIP + ":" + packet.destPort;
                    }
                    else
                    {
                        key = packet.sourcePort;
                    }

                    DelegateDataGridViewAddRow addRow = delegate
                    {
                        DataGridViewRow r = new DataGridViewRow();
                        int index = dataGridView1.Rows.Add(new DataGridViewRow() { });
                        if (NetProcessAPI.dicNetToProcess.ContainsKey(key))
                        {
                            lock (NetProcessAPI.dicLock)
                            {
                                try
                                {
                                    dataGridView1.Rows[index].Cells[0].Value = NetProcessAPI.dicNetToProcess[key].icon;
                                }
                                catch
                                {
                                    dataGridView1.Rows[index].Cells[0].Value = null;
                                }

                                
                               
                                
                                dataGridView1.Rows[index].Cells[1].ToolTipText = NetProcessAPI.dicNetToProcess[key].path; ;
                                dataGridView1.Rows[index].Cells[1].Value = NetProcessAPI.dicNetToProcess[key].name;

                            }

                        }
                        else
                        {

                            dataGridView1.Rows[index].Cells[0].Value = Properties.Resources.ConfigureWERTask;
                           
                            
                            dataGridView1.Rows[index].Cells[1].Value = "未知";
                        }

                        dataGridView1.Rows[index].Cells[2].Value = packet.protocol; dataGridView1.Rows[index].Cells[3].Value = src; dataGridView1.Rows[index].Cells[4].Value = dst;
                    };
                    try
                    {
                        this.dataGridView1.Invoke(addRow);
                    }
                    catch
                    {

                    }
                }
            }



            try
            {

                foreach (DataGridViewRow row in dataGridView1.Rows)
                {

                    var result = datas[row.Index];
                    int dropCount = result.Where(x => x == -1).Count();
                    int packCount = result.Count();
                    List<long> r = result.ToArray().ToList();
                    r.RemoveAll(x => x == -1);
                    long maxValue = r.Count == 0 ? 0 : r.Max();
                    long minValue = r.Count == 0 ? 0 : r.Min();
                    long aveValue = r.Count == 0 ? 0 : Convert.ToInt32(r.Average());
                    if (aveValue > 20)
                    {
                        minValue = r.Count == 0 ? 0 : r.Where(x => x > 1).Min();
                        aveValue = r.Count == 0 ? 0 : Convert.ToInt32(r.Where(x => x > 1).Average());
                    }
                    long totalValue = r.Count == 0 ? 0 : r.Where(x => x != -1).Sum();

                    ulong len = dataLen[row.Index];

                    int dropPercent = 0;
                    if (packCount != 0)
                    {
                        dropPercent = dropCount * 100 / packCount;
                    }
                    bool f2 = true;
                    f2 = (comboindex == 0) || (comboindex == 1 && row.Cells[2].Value.ToString() == "TCP") || (comboindex == 2 && row.Cells[2].Value.ToString() == "UDP");


                    //名称包含
                    bool f1 = textBox1.Text.Trim() == "" || row.Cells[1].Value.ToString().ToLower().IndexOf(textBox1.Text.ToLower()) >= 0 || (checkBox1.Checked && (row.Cells[1].Value.ToString().ToLower().IndexOf("未知") >= 0 || row.Cells[1].Value.ToString().ToLower().IndexOf("idle") >= 0));
                    //协议

                    //IP
                    bool f3 = textBox2.Text.Trim() == "" || row.Cells[4].Value.ToString().ToLower().IndexOf(textBox2.Text.ToLower()) >= 0;
                    //包数量
                    bool f4 = textBox3.Text.Trim() == "" || isNumber(textBox3.Text) && packCount >= Convert.ToInt32(textBox3.Text);
                    //名称不含
                    bool f5 = textBox4.Text.Trim() == "" || row.Cells[1].Value.ToString().ToLower().IndexOf(textBox4.Text.ToLower()) < 0;

                    DataRow drow = new DataRow();
                    if (f1 && f2 && f3 && f4 && f5)
                    {
                        drow.Visible = true;
                    }
                    else
                    {
                        drow.Visible = false;
                    }
                    drow.rowIndex = row.Index;
                    drow.row5Value = packCount;
                    drow.row6Value = maxValue.ToString() + "/" + minValue.ToString() + "/" + aveValue.ToString();
                    drow.setRow6Color(aveValue);
                    drow.row7Value = dropCount;
                    drow.row8Value = dropPercent.ToString() + "%";
                    drow.setRow78Color(dropPercent);
                    drow.row9Value = dataRST[row.Index];
                    drow.row9Color = dataRST[row.Index] > 0 ? Color.Red : Color.Green;
                    drow.setRow10(len);

                    if (row.Cells[5].Value == null)
                    {
                        if (dicDataRows.ContainsKey(row.Index))
                        {
                            dicDataRows[row.Index] = drow;
                        }
                        else
                        {
                            dicDataRows.Add(row.Index, drow);
                        }

                    }
                    else if (row.Cells[5].Value.ToString() == drow.row5Value.ToString() && row.Cells[6].Value.ToString() == drow.row6Value.ToString() && row.Cells[7].Value.ToString() == drow.row7Value.ToString() && row.Cells[8].Value.ToString() == drow.row8Value.ToString()
                       && row.Cells[9].Value.ToString() == drow.row9Value.ToString() && row.Cells[10].Value.ToString() == drow.row10Value.ToString() && row.Visible == drow.Visible
                       && row.Cells[6].Style.ForeColor == drow.row6Color && row.Cells[7].Style.ForeColor == drow.row7Color && row.Cells[8].Style.ForeColor == drow.row8Color && row.Cells[9].Style.ForeColor == drow.row9Color && row.Cells[10].Style.ForeColor == drow.row10Color)
                    {

                    }
                    else
                    {

                        if (dicDataRows.ContainsKey(row.Index))
                        {
                            dicDataRows[row.Index] = drow;
                        }
                        else
                        {
                            dicDataRows.Add(row.Index, drow);
                        }
                    }



                }


            }
            catch 
            {

            }


        }



        private bool isNumber(string value)
        {
            return Regex.IsMatch(value, @"\d+");
        }

        private void Form1_SizeChanged(object sender, EventArgs e)
        {
            dataGridView1.Size = new Size(this.Size.Width - 20, this.Size.Height - 90);
        }

        private void dataGridView1_CellValueChanged(object sender, DataGridViewCellEventArgs e)
        {

        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {

        }

        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            System.Environment.Exit(0);
        }

        private void dataGridView1_ColumnWidthChanged(object sender, DataGridViewColumnEventArgs e)
        {
            dataGridView1.Width = dataGridView1.Columns.GetColumnsWidth(DataGridViewElementStates.Visible) + 20;
            this.Width = dataGridView1.Width + 20;
            if (this.Width < checkBox2.Right) this.Width = checkBox2.Right + 20;
        }

        private void checkBox2_CheckedChanged(object sender, EventArgs e)
        {
            this.TopMost = checkBox2.Checked;
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {
       
            if(e.ColumnIndex==1)
            {
                int Rowindex = e.RowIndex;

                string srcIP = dataGridView1.Rows[Rowindex].Cells[3].Value.ToString();
                string dstIP = dataGridView1.Rows[Rowindex].Cells[4].Value.ToString().Split(':')[0];
                string dstPort = dataGridView1.Rows[Rowindex].Cells[4].Value.ToString().Split(':')[1];
                string protocol = dataGridView1.Rows[Rowindex].Cells[2].Value.ToString();
                byte[] content = udpData[Rowindex];
                Form2 frm2 = new Form2(srcIP, dstIP, dstPort, protocol, content);
                frm2.ShowDialog();
                frm2.Dispose();
            }
            else if (e.ColumnIndex==4 && dataGridView1.Rows[e.RowIndex].Cells[4].Style.ForeColor==Color.Green)
            {
                Form3 frm3 = new Form3();
                frm3.textBox1.Text = dataGridView1.Rows[e.RowIndex].Cells[4].ToolTipText.Replace("\r\n", "\r\n\r\n");
                frm3.ShowDialog();
                frm3.Dispose();
            }
           


        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            timer1.Enabled = false;
          
           
            comboindex = comboBox1.SelectedIndex;
            List<DataRow> rows = new List<DataRow>();
            lock (rowLock)
            {
                rows = dicDataRows.Values.ToList();
                dicDataRows.Clear();
            }
            foreach (DataRow drow in rows)
            {
                dataGridView1.Rows[drow.rowIndex].Visible = drow.Visible;
                dataGridView1.Rows[drow.rowIndex].Cells[5].Value = drow.row5Value; dataGridView1.Rows[drow.rowIndex].Cells[6].Value = drow.row6Value; dataGridView1.Rows[drow.rowIndex].Cells[7].Value = drow.row7Value;
                dataGridView1.Rows[drow.rowIndex].Cells[8].Value = drow.row8Value; dataGridView1.Rows[drow.rowIndex].Cells[9].Value = drow.row9Value; dataGridView1.Rows[drow.rowIndex].Cells[10].Value = drow.row10Value;
                dataGridView1.Rows[drow.rowIndex].Cells[6].Style.ForeColor = drow.row6Color; dataGridView1.Rows[drow.rowIndex].Cells[7].Style.ForeColor = drow.row7Color;
                dataGridView1.Rows[drow.rowIndex].Cells[8].Style.ForeColor = drow.row8Color; dataGridView1.Rows[drow.rowIndex].Cells[9].Style.ForeColor = drow.row9Color; dataGridView1.Rows[drow.rowIndex].Cells[10].Style.ForeColor = drow.row10Color;
            }
         
            timer1.Enabled = true;

        }

        Dictionary<string, PacketDotNet.DnsPacket> dicDNS = new Dictionary<string, PacketDotNet.DnsPacket>();
        private void timer2_Tick(object sender, EventArgs e)
        {
            timer2.Enabled = false;
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            sw.Start();

            dicDNS = cp.getDnsResolve(dicDNS);


            sw.Stop();
            if (sw.ElapsedMilliseconds > 1)
            {
                System.Diagnostics.Debug.Print((sw.ElapsedMilliseconds).ToString());
            }

      

            foreach(DataGridViewRow row in dataGridView1.Rows)
            {
                if(!row.Cells[4].ToolTipText.StartsWith("位置") && ipSearch!=null)
                {
                    try
                    {
                        var location = ipSearch.GetIPLocation(row.Cells[4].Value.ToString().Split(':')[0]);
                        string lct = "位置：";
                        lct += location.area == null ? "" : location.area + " ";
                        lct += location.country == null ? "" : location.country;
                        row.Cells[4].ToolTipText = lct+"\r\n" + row.Cells[4].ToolTipText;
                        if (row.Cells[4].Style.ForeColor != Color.Green)
                            row.Cells[4].Style.ForeColor = Color.Blue;
                    }
                    catch
                    {

                    }


                }
                if(row.Cells[4].Style.ForeColor!=Color.Green)
                {
                    try
                    {
                        string ip = row.Cells[4].Value.ToString().Split(':')[0];
                        if (dicDNS.ContainsKey(ip))
                        {
                            row.Cells[4].Style.ForeColor = Color.Green;
                            PacketDotNet.DnsPacket packet = dicDNS[ip];
                            StringBuilder sb = new StringBuilder();
                            sb.AppendLine("解析请求：");
                            foreach (var d in packet.Questions)
                            {
                                sb.AppendLine("  " + d.name + " " + d.dnsType.ToString() + " " + d.dnsClass.ToString());
                            }
                            sb.AppendLine();
                            sb.AppendLine("解析响应：");
                            foreach (var d in packet.Records)
                            {
                                sb.AppendLine("  " + d.Name + " " + d.QType.ToString() + " " + d.QClass.ToString() + " " + d.RDDate.ToString());
                            }
                            row.Cells[4].ToolTipText += "\r\n\r\n" + sb.ToString();

                        }
                    }
                    catch
                    {

                    }
                  
                }
            }


            timer2.Enabled = true;
        }
    }

    public class DataRow
    {
        public int rowIndex { get; set; }
        public bool Visible { get; set; }
        public object row5Value { get; set; }
        public object row6Value { get; set; }
        public object row7Value { get; set; }
        public object row8Value { get; set; }
        public object row9Value { get; set; }
        public object row10Value { get; set; }
        public Color row6Color { get; set; }
        public Color row7Color { get; set; }
        public Color row8Color { get; set; }
        public Color row9Color { get; set; }
        public Color row10Color { get; set; }
        public void setRow6Color(long avg)
        {
            if (avg < 100)
            {
                row6Color = Color.Green;
            }
            else if (avg < 200)
            {
                row6Color = Color.Blue;
            }
            else
            {
                row6Color = Color.Red;
            }
        }

        public void setRow78Color(int dropPercent)
        {
            if (dropPercent >= 5)
            {
                row7Color = Color.Red;
                row8Color = Color.Red;

            }
            else
            {
                row7Color = Color.Green;
                row8Color = Color.Green;
            }
        }



        public void setRow10(ulong len)
        {
            if (len < 1024)
            {
                row10Value = len.ToString() + "B";
            }
            else if (len < 1024 * 1024)
            {
                row10Value = (len / 1024.0).ToString("f1") + "KB";
                row10Color = Color.Green;
            }
            else if (len < 1024 * 1024 * 1024)
            {
                row10Value = (len / 1024 / 1024.0).ToString("f2") + "MB";
                row10Color = Color.Blue;
            }
            else
            {
                row10Value = (len / 1024 / 1024 / 1024.0).ToString("f2") + "GB";
                row10Color = Color.Red;
            }


        }

    }

}
