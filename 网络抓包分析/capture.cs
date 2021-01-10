using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpPcap;
using PacketDotNet;
using System.Net.Sockets;
using System.Security.Policy;
using System.Net.NetworkInformation;
using System.Diagnostics.Eventing.Reader;

namespace 网络抓包分析
{

  
    public class PacketClass
    {
        public string protocol { get; set; }
        public string srcIP { get; set; }
        public string sourcePort { get; set; }
        public string destIP { get; set; }
        public string destPort { get; set; }

        public TcpPacket tcpPacket { get; set; }
        public UdpPacket udpPacket { get; set; }
        public ulong PacketLength { get; set; }
        public PosixTimeval recvTime { get; set; }
    
    }

    public class PacketStatisticsTime
    {
        public string protocol { get; set; }
        public string srcIP { get; set; }
        public string sourcePort { get; set; }
        public string destIP { get; set; }
        public string destPort { get; set; }
        public ulong totalTime { get; set; }
    }
    public class PacketStatistics
    {
        public string protocol { get; set; }
        public string srcIP { get; set; }
        public string sourcePort { get; set; }
        public string destIP { get; set; }
        public string destPort { get; set; }
        public ulong PacketLength { get; set; }

        public byte[] udpPacketContent { get; set; }

        /// <summary>
        /// 毫秒
        /// </summary>
        public long answerTime { get; set; }
        public bool isimTimeout { get; set; }

        public bool isRST { get; set; }
    }
    public class AnalyticsPackets
    {
       
       
        public AnalyticsPackets()
        {
            packetStatistics = new List<PacketStatistics>();
            packets = new List<PacketClass>();
            TotalTime = new Dictionary<string, ulong>();
            TcpdataLen = 0;
            UdpdataLen = 0;
        }
        public List<PacketStatistics> packetStatistics { get; set; }
        public List<PacketClass> packets { get; set; }
        public ulong TcpdataLen { get; set; }
        public ulong UdpdataLen { get; set; }
        public Dictionary<string,ulong> TotalTime { get; set; }
    }
    public class captureClass
    {
        List<UdpPacket> dnsPackets = new List<UdpPacket>();
        public List<RawCapture> PacketQueue = new List<RawCapture>();
        public object QueueLock = new object();
        public List<string> srcIPList = new List<string>();
        PacketArrivalEventHandler arrivalEventHandler;
        public List<string> activeInterface = new List<string>();
        private object dnsPacketLock = new object();

        public captureClass()
        {
            getSrcIP();
            srcIPList = srcIPList.Distinct().ToList();
        }

        public void getSrcIP()
        {
            
            var Ani = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var ni in Ani)
            {
                var ua = ni.GetIPProperties().UnicastAddresses.ToArray();

                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (var va in ua)
                    {
                        if (va.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            string ip = va.Address.ToString();
                            if (ip.StartsWith("127.") || ip.StartsWith("169."))
                            {
                                continue;
                            }
                            srcIPList.Add(ip);
                            activeInterface.Add(ni.Id);
                        }
                    }
                }

            }
            activeInterface = activeInterface.Distinct().ToList();
        }
        public bool isActiveInterface(string interfaceID)
        {
            if (activeInterface.Find(x => interfaceID.Contains(x)) != null)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        public void startCatch()
        {

            foreach (SharpPcap.Npcap.NpcapDevice device in CaptureDeviceList.Instance)
            {
                if (!isActiveInterface(device.Name)) continue;


                arrivalEventHandler = new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);
                device.OnPacketArrival += arrivalEventHandler;

                device.Open(DeviceMode.Normal);
                string srcIP = "(host " + string.Join(" or host ", srcIPList) + ")";
                device.Filter = "ether proto 0x08864 or udp or tcp";

                device.StartCapture();
                
            }
        }

    

        public Dictionary<string, DnsPacket> getDnsResolve(Dictionary<string, DnsPacket> dicDNS)
        {
       
            List<UdpPacket> packets;
            lock(dnsPacketLock)
            {
    
                packets = dnsPackets;
                dnsPackets = new List<UdpPacket>();
            }
            foreach(UdpPacket packet in packets)
            {
               if(packet.PayloadData!=null && packet.PayloadData.Length>12)
                {
                    DnsPacket dnspacket = new DnsPacket();
                    if(dnspacket.Parse(packet.PayloadData))
                    {
                        foreach( var d in dnspacket.Records.Where(x => x.QType == DnsQueryType.A ).ToList())
                        {
                            string addr= ((A_RR)d.RDDate).ToString();
                            if (!dicDNS.ContainsKey(addr))
                            {
                                dicDNS.Add(addr, dnspacket);
                            }
                        }



                    }
                }

            }

            return dicDNS;
        }
        public PacketClass readPacket(RawCapture packet)
        {
            IPv4Packet ipPacket;
            PacketClass result = new PacketClass();
            if (packet.LinkLayerType == LinkLayers.Ethernet)
            {
                EthernetPacket ePacket = (EthernetPacket)Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                if (ePacket.Type == EthernetType.IPv4)
                {
                    ipPacket = (IPv4Packet)ePacket.PayloadPacket;

                }
                else if (ePacket.Type == EthernetType.PppoeSessionStage)
                {
                    try
                    {
                        ipPacket = (IPv4Packet)ePacket.PayloadPacket.PayloadPacket.PayloadPacket;
                        if (ipPacket == null) return null;
                    }
                    catch
                    {
                        return null;
                    }
                }
                else
                {
                    return null;
                }
            }
            else
            {
                return null;
            }

            result.srcIP = ipPacket.SourceAddress.ToString();
            result.destIP = ipPacket.DestinationAddress.ToString();

            if (ipPacket.Protocol == PacketDotNet.ProtocolType.Tcp)
            {
                TcpPacket tcpP = (TcpPacket)ipPacket.PayloadPacket;
                tcpP.CongestionWindowReduced = false;
                tcpP.NonceSum = false;
                tcpP.ExplicitCongestionNotificationEcho = false;
                tcpP.Urgent = false;

                result.tcpPacket = tcpP;
                result.sourcePort = tcpP.SourcePort.ToString();
                result.destPort = tcpP.DestinationPort.ToString();
                result.recvTime = packet.Timeval;
                result.PacketLength = Convert.ToUInt64(packet.Data.Length);
                result.protocol = "TCP";

            }
            else if (ipPacket.Protocol == PacketDotNet.ProtocolType.Udp)
            {
                UdpPacket udpP = (UdpPacket)ipPacket.PayloadPacket;
                if (udpP != null)
                {
                    result.udpPacket = udpP;
                    result.sourcePort = udpP.SourcePort.ToString();
                    result.destPort = udpP.DestinationPort.ToString();
                    result.recvTime = packet.Timeval;
                    result.PacketLength = Convert.ToUInt64(packet.Data.Length);
                    result.protocol = "UDP";
                    if(udpP.SourcePort==53)
                    {
                        lock(dnsPacketLock)
                        {
                            dnsPackets.Add(udpP);
                        }
                        
                    }

                }

            }

            return result;
        }
        public List<PacketClass> getPackets()
        {

            List<RawCapture> ourQueue;
            List<PacketClass> result = new List<PacketClass>();
            lock (QueueLock)
            {
                // swap queues, giving the capture callback a new one

                ourQueue = PacketQueue;
                PacketQueue = new List<RawCapture>();
            }
            foreach (var packet in ourQueue)
            {
                PacketClass d = readPacket(packet);
                if (d != null)
                {
                    result.Add(d);
                }
            }
            return result;



        }


        public AnalyticsPackets AnalyePacket(List<PacketClass> packets, ulong _tcpDatalen, ulong _udpDatalen)
        {
            AnalyticsPackets analyticsPackets = new AnalyticsPackets();

            /*
            while(packets.Count>0)
            {
                
                if (!srcIPList.Contains(packets.First().srcIP))
                {
                    packets.RemoveAt(0);
                }
                else
                {
                    break;
                }

            }
            */

            var tcpPackets = packets.Where(x => x.protocol == "TCP").ToList();
            var udpPackets = packets.Where(x => x.protocol == "UDP").ToList();

            //分析tcp包
            while (tcpPackets.Count() > 0)
            {
                var currentPacket = tcpPackets.First();

                //0x10:ack包，,0x12:syn ack 包,0x12:syn rst 包，rst包 没有前序，不做统计
                if (!srcIPList.Contains(currentPacket.srcIP) || currentPacket.tcpPacket.Flags == 0x12 || currentPacket.tcpPacket.Reset == true)
                {
                    tcpPackets.RemoveAt(0);
                    continue;
                }

                var currentIPpackets = tcpPackets.FindAll(x => (x.srcIP == currentPacket.srcIP && x.sourcePort == currentPacket.sourcePort && x.destIP == currentPacket.destIP && x.destPort == currentPacket.destPort)
                  || (x.srcIP == currentPacket.destIP && x.sourcePort == currentPacket.destPort && x.destIP == currentPacket.srcIP && x.destPort == currentPacket.sourcePort));




                //只有1个请求包无其他包的情况
                if (currentIPpackets.Count == 1)
                {
                    if (tcpPackets.Last().recvTime.Date.Ticks - currentPacket.recvTime.Date.Ticks > 2000 * 10000) //当延迟大于2000，算丢包,加入统计
                    {

                        //最后一个包为ack包，不做丢包判断
                        if (currentPacket.tcpPacket.Flags == 0x10)
                        {
                            tcpPackets.RemoveAt(0);
                            continue;
                        }
                        analyticsPackets.packetStatistics.Add(new PacketStatistics()
                        {
                            answerTime = -1,
                            destIP = currentPacket.destIP,
                            destPort = currentPacket.destPort,
                            isimTimeout = true,
                            protocol = currentPacket.protocol,
                            sourcePort = currentPacket.sourcePort,
                            srcIP = currentPacket.srcIP,
                            isRST = false
                        });

                    }
                    else
                    {
                        analyticsPackets.packets.Add(currentPacket); //延迟小于1000，加入下次分析队列
                        
                    }
                    tcpPackets.RemoveAt(0);
                    continue;
                }
                else
                {
                    ulong dataLen = _tcpDatalen;

                    foreach (var cp in currentIPpackets)
                    {
                        dataLen += cp.PacketLength;
                        if (currentPacket != null && cp.srcIP != currentPacket.srcIP)
                        {
                            analyticsPackets.packetStatistics.Add(new PacketStatistics()
                            {
                                answerTime = (cp.recvTime.Date.Ticks - currentPacket.recvTime.Date.Ticks) / 10000,
                                destIP = currentPacket.destIP,
                                destPort = currentPacket.destPort,
                                isimTimeout = false,
                                protocol = currentPacket.protocol,
                                sourcePort = currentPacket.sourcePort,
                                srcIP = currentPacket.srcIP,
                                PacketLength = dataLen,

                                isRST = cp.tcpPacket.Reset


                            });
                            currentPacket = null;
                            dataLen = 0;
                        }
                        else if (currentPacket == null && srcIPList.Contains(cp.srcIP) && cp.tcpPacket.Flags != 0x10 || cp.tcpPacket.Flags != 0x12 || cp.tcpPacket.Reset == false)
                        {
                            currentPacket = cp;
                        }

                    }
                    analyticsPackets.TcpdataLen = dataLen;

                }
                if (currentPacket != null)
                {
                    analyticsPackets.packets.Add(currentPacket);
                }

                var _cPacket = tcpPackets.First();
                tcpPackets.RemoveAll(x => (x.srcIP == _cPacket.srcIP && x.sourcePort == _cPacket.sourcePort && x.destIP == _cPacket.destIP && x.destPort == _cPacket.destPort)
                 || (x.srcIP == _cPacket.destIP && x.sourcePort == _cPacket.destPort && x.destIP == _cPacket.srcIP && x.destPort == _cPacket.sourcePort));




            }


            while (udpPackets.Count() > 0)
            {
                var currentPacket = udpPackets.First();
                if (!srcIPList.Contains(currentPacket.srcIP))
                {
                    udpPackets.RemoveAt(0);
                    continue;
                }

                var currentIPpackets = udpPackets.FindAll(x => (x.srcIP == currentPacket.srcIP && x.sourcePort == currentPacket.sourcePort && x.destIP == currentPacket.destIP && x.destPort == currentPacket.destPort)
                  || (x.srcIP == currentPacket.destIP && x.sourcePort == currentPacket.destPort && x.destIP == currentPacket.srcIP && x.destPort == currentPacket.sourcePort));

                //只有1个请求包无其他包的情况
                if (currentIPpackets.Count == 1)
                {
                    if (udpPackets.Last().recvTime.Date.Ticks - currentPacket.recvTime.Date.Ticks > 3000 * 10000) //当延迟大于2000，算丢包,加入统计
                    {
                        //udp包不记录丢包率;
                        /*
                        analyticsPackets.packetStatistics.Add(new PacketStatistics()
                        {
                            answerTime = -1,
                            destIP = currentPacket.destIP,
                            destPort = currentPacket.destPort,
                            isimTimeout = true,
                            protocol = currentPacket.protocol,
                            sourcePort = currentPacket.sourcePort,
                            srcIP = currentPacket.srcIP,
                            isRST = false
                        });
                        */

                    }
                    else
                    {
                        analyticsPackets.packets.Add(currentPacket); //延迟小于3000，加入下次分析队列
                    }
                    udpPackets.RemoveAt(0);
                    continue;
                }
                else
                {
                    bool addContent = true;
                    ulong dataLen = _udpDatalen;
                    foreach (var cp in currentIPpackets)
                    {
                        dataLen += cp.PacketLength;
                        if (currentPacket != null && cp.srcIP != currentPacket.srcIP)
                        {
                            var p = new PacketStatistics()
                            {
                                answerTime = (cp.recvTime.Date.Ticks - currentPacket.recvTime.Date.Ticks) / 10000,
                                destIP = currentPacket.destIP,
                                destPort = currentPacket.destPort,
                                isimTimeout = false,
                                protocol = currentPacket.protocol,
                                sourcePort = currentPacket.sourcePort,
                                srcIP = currentPacket.srcIP,
                                PacketLength = dataLen,

                                isRST = false

                            };
                            if(addContent)
                            {
                                if (srcIPList.Contains(currentPacket.srcIP) && currentPacket.udpPacket.PayloadData.Length > 1)
                                {
                                    p.udpPacketContent = currentPacket.udpPacket.PayloadData;
                                    addContent = false;
                                }
                                    
                            }
                            analyticsPackets.packetStatistics.Add(p);
                            currentPacket = null;
                            dataLen = 0;
                        }
                        else if (currentPacket == null && srcIPList.Contains(cp.srcIP))
                        {
                            currentPacket = cp;
                        }

                    }
                    analyticsPackets.UdpdataLen = dataLen;

                }
                if (currentPacket != null)
                {
                    analyticsPackets.packets.Add(currentPacket);
                }
                var _cPacket = udpPackets.First();
                udpPackets.RemoveAll(x => (x.srcIP == _cPacket.srcIP && x.sourcePort == _cPacket.sourcePort && x.destIP == _cPacket.destIP && x.destPort == _cPacket.destPort)
                 || (x.srcIP == _cPacket.destIP && x.sourcePort == _cPacket.destPort && x.destIP == _cPacket.srcIP && x.destPort == _cPacket.sourcePort));




            }
            return analyticsPackets;
        }

        public void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {


            lock (QueueLock)
            {


                PacketQueue.Add(e.Packet);
                //System.Diagnostics.Debug.Print(PacketQueue.Count.ToString());

            }


        }


    }
}
