using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;

namespace 网络抓包分析
{
    public partial class Form2 : Form
    {
        public Form2()
        {
            InitializeComponent();
        }
        string srcIP, dstIP, dstPort, protocol;
        byte[] udpContent;
        List<long> ping32List = new List<long>();
        List<long> ping1024List = new List<long>();
        List<long> TcpPingList = new List<long>();
        List<long> udpPingList = new List<long>();

        public Form2(string srcIP,string dstIP,string dstPort,string protocol, byte[] udpContent)
        {
            InitializeComponent();
            this.srcIP = srcIP;
            this.dstIP = dstIP;
            this.dstPort = dstPort;
            this.protocol = protocol;
            this.udpContent = udpContent;
            this.label1.Text = $"源IP：{srcIP}      目标IP：{dstIP}      目标端口：{dstPort}      协议：{protocol}";
        }

        private delegate void Delegatelabel4();
        private delegate void Delegatelabel3();
        private delegate void Delegatelabel6();
        private void Form2_Load(object sender, EventArgs e)
        {

            Task<long> taskping32 = new Task<long>(() => ping32(dstIP));
            taskping32.Start();
            taskping32.ContinueWith(t => changePing32(t, 1));


            Task<long> taskping1024 = new Task<long>(() => ping1024(dstIP));
            taskping1024.Start();
            taskping1024.ContinueWith(t => changePing1024(t, 1));

            if (protocol == "TCP")
            {
                label8.Text = "非udp协议";
                Task<int> taskTping = new Task<int>(() => testTcp(dstIP, Convert.ToInt32(dstPort), srcIP, 1000));
                taskTping.Start();
                taskTping.ContinueWith(tt => changeTping(tt, 1));
            }
            else
            {
                label6.Text = "非tcp协议";
                Task<int> taskUping = new Task<int>(() => udpPing(srcIP, dstIP, Convert.ToInt32(dstPort), 1000));
                taskUping.Start();
                taskUping.ContinueWith(tt => changeUping(tt, 1));
            }
            


        }
        bool doExit = false;

        private void Form2_FormClosing(object sender, FormClosingEventArgs e)
        {
            doExit = true;
        }


        private void changePing1024(Task<long> t, int ping1024Count)
        {
            ping1024List.Add(t.Result);
            long drop = ping1024List.Where(x => x == -1).Count();
            var _list = ping1024List.Where(x => x >= 0).ToList();
            long max = _list.Count == 0 ? 0 : +_list.Max();
            long min = _list.Count == 0 ? 0 : _list.Min();
            double avg = _list.Count == 0 ? 0 : _list.Average();
            double dropPercent = drop * 100.0 / ping1024List.Count;
            Delegatelabel3 d3 = delegate { label3.Text = $"数量:{ping1024Count},最大值：{max},最小值:{min},平均值:{avg.ToString("f0")},丢包{drop},丢包率{dropPercent.ToString("f1") + "%"}"; };
            try
            {
                label3.Invoke(d3);
            }
            catch
            {

            }

            if (ping1024Count < 1000 && !doExit)
            {
                ping1024Count++;
                Task<long> task = new Task<long>(() => ping1024(dstIP));
                task.Start();
                task.ContinueWith(tt => changePing1024(tt, ping1024Count));

            }
        }

        private void changePing32(Task<long> t,int ping32Count)
        {
            ping32List.Add(t.Result);
            long drop = ping32List.Where(x => x == -1).Count();
            var _list = ping32List.Where(x => x >= 0).ToList();
            long max = _list.Count == 0 ? 0 : +_list.Max();
            long min = _list.Count == 0 ? 0 : _list.Min();
            double avg = _list.Count == 0 ? 0 : _list.Average();
            double dropPercent = drop * 100.0 / ping32List.Count;
            Delegatelabel4 d4 = delegate { label4.Text = $"数量:{ping32Count},最大值：{max},最小值:{min},平均值:{avg.ToString("f0")},丢包{drop},丢包率{dropPercent.ToString("f1") + "%"}"; };
            try
            {
                label4.Invoke(d4);
            }
            catch
            {

            }
            

            if (ping32Count < 1000 && !doExit)
            {
                ping32Count++;
                Task<long> task = new Task<long>(() => ping32(dstIP));
                task.Start();
                task.ContinueWith(tt => changePing32(tt, ping32Count));

            }
        }


        private void changeTping(Task<int> t, int count)
        {
            TcpPingList.Add(t.Result);
            long drop = TcpPingList.Where(x => x == -1).Count();
            var _list = TcpPingList.Where(x => x >= 0).ToList();
            long max = _list.Count == 0 ? 0 : +_list.Max();
            long min = _list.Count == 0 ? 0 : _list.Min();
            double avg = _list.Count == 0 ? 0 : _list.Average();
            double dropPercent = drop * 100.0 / TcpPingList.Count;
            Delegatelabel6 d6 = delegate { label6.Text = $"数量:{count},最大值：{max},最小值:{min},平均值:{avg.ToString("f0")},丢包{drop},丢包率{dropPercent.ToString("f1") + "%"}"; };
            try
            {
                label6.Invoke(d6);
            }
            catch
            {

            }


            if (count < 1000 && !doExit)
            {
                count++;
                Task<int> task = new Task<int>(() => testTcp(dstIP, Convert.ToInt32(dstPort), srcIP, 1000));
                task.Start();
                task.ContinueWith(tt => changeTping(tt, count));

            }
        }


        private void changeUping(Task<int> t, int count)
        {
            udpPingList.Add(t.Result);
            long drop = udpPingList.Where(x => x == -1).Count();
            var _list = udpPingList.Where(x => x >= 0).ToList();
            long max = _list.Count == 0 ? 0 : +_list.Max();
            long min = _list.Count == 0 ? 0 : _list.Min();
            double avg = _list.Count == 0 ? 0 : _list.Average();
            double dropPercent = drop * 100.0 / udpPingList.Count;
            Delegatelabel6 d6 = delegate { label8.Text = $"数量:{count},最大值：{max},最小值:{min},平均值:{avg.ToString("f0")},丢包{drop},丢包率{dropPercent.ToString("f1") + "%"}"; };
            try
            {
                label8.Invoke(d6);
            }
            catch
            {

            }


            if (count < 1000 && !doExit)
            {
                count++;
                Task<int> task= new Task<int>(() => udpPing(srcIP, dstIP, Convert.ToInt32(dstPort), 1000));
                task.Start();
                task.ContinueWith(tt => changeUping(tt, count));

            }
        }

        private long ping32(string dstIP)
        {
            Ping ping = new Ping();

            byte[] b = new byte[32];
            b.AsSpan<byte>().Fill(97);
            
           
            var reply = ping.Send(dstIP, 1000, b);
            if(reply.Status== IPStatus.Success)
            {
                return reply.RoundtripTime;
            }
            else
            {
                return -1;
            }
            
        }

        private long ping1024( string dstIP)
        {
            Ping ping = new Ping();
            byte[] b = new byte[1024];
            b.AsSpan<byte>().Fill(97);
            
            var reply = ping.Send(dstIP, 1000, b);
            if (reply.Status == IPStatus.Success)
            {
                return reply.RoundtripTime;
            }
            else
            {
                return -1;
            }

        }


        private int testTcp(string host, int port,string srcIP, int timeout)
        {



            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Parse(srcIP), 0));
            DateTime startTime = DateTime.Now;
            IAsyncResult connResult = socket.BeginConnect(host, port, null, null);
            connResult.AsyncWaitHandle.WaitOne(timeout, true);
            DateTime endtime = DateTime.Now;
            if (connResult.IsCompleted)
            {
                socket.Close();
                return Convert.ToInt32((endtime - startTime).TotalMilliseconds);
            }
            else
            {
                socket.Close();
                return -1;
            }
        }

        private int udpPing(string srcIP,string dstIP,int dstPort,int timeout)
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Parse(srcIP), 0));

            DateTime startTime = DateTime.Now;
            socket.Connect(dstIP, dstPort);
            socket.Send(udpContent);
            byte[] recv = new byte[1500];
            IAsyncResult connResult = socket.BeginReceive(recv, 0, 1500, SocketFlags.None, null, null);
            connResult.AsyncWaitHandle.WaitOne(timeout, true);
            DateTime endtime = DateTime.Now;
            if (connResult.IsCompleted)
            {
                socket.Close();
                return Convert.ToInt32((endtime - startTime).TotalMilliseconds);
            }
            else
            {
                socket.Close();
                return -1;
            }
        }

    }
}
