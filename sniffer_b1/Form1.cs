using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using SharpPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Threading;

namespace sniffer
{
    public partial class Form1 : Form
    {
        public CaptureDeviceList devices;
        private ICaptureDevice _device = null;  //捕获网卡
        private int QueueNum = 0;           //读取队列号
        private List<List<RawCapture>> PacketQueue = new List<List<RawCapture>>();      //捕获数据存放在列表中
        private List<RawCapture> AllPacketQ = new List<RawCapture>();
        private List<RawCapture> ArpPacketQ = new List<RawCapture>();
        private List<RawCapture> IpPacketQ = new List<RawCapture>();
        private List<RawCapture> TcpPacketQ = new List<RawCapture>();
        private List<RawCapture> UdpPacketQ = new List<RawCapture>();
        private List<RawCapture> HttpPacketQ = new List<RawCapture>();
        private Thread _Backgroundthread;       //后台处理列表数据放入listview
        private object QueueLock = new object();    //防止数据入队和读取同时进行发生错误
//        private bool _threadabort;          //是否应该停止线程

        public Form1()
        {
            InitializeComponent();
            button2.Enabled = false;
            PacketQueue.Add(AllPacketQ);
            PacketQueue.Add(ArpPacketQ);
            PacketQueue.Add(IpPacketQ);
            PacketQueue.Add(TcpPacketQ);
            PacketQueue.Add(UdpPacketQ);
            PacketQueue.Add(HttpPacketQ);
            devices = CaptureDeviceList.Instance;
            //显示网卡信息
            foreach (var dev in devices)
            {
                this.comboBox1.Items.Add(dev.Description);
            }
            
        }
        private void Shutdown()
        {
            if(_device != null)
            {
                _device.StopCapture();
                _device.Close();
                _device = null;
//                _Backgroundthread.Abort();
//                _threadabort = true;
                textBox1.ReadOnly = false;
//                MessageBox.Show(PacketQueue.Capacity.ToString()+" "+PacketQueue.Count.ToString());
                button1.Enabled = true;
                button2.Enabled = false;
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (this.comboBox1.SelectedIndex >= 0)
            {
                try
                {
                    //Register our handler function to the 'packet arrival' event
                    _device = devices[this.comboBox1.SelectedIndex];
                    _device.OnPacketArrival +=
                        new PacketArrivalEventHandler(device_OnPacketArrival);
                    _device.Open();
                    _device.Filter = textBox1.Text;
                    for (int i = 0; i <= 5; i++)
                        PacketQueue[i].Clear();
                    _device.StartCapture();
                    try
                    {
                        if (_Backgroundthread.IsAlive)
                        {
                            _Backgroundthread.Abort();
                        }
                    }
                    catch
                    {
                    }
                    ThreadStart threadstart = new ThreadStart(Backgroundprocess);
                    _Backgroundthread = new Thread(threadstart);
                    _Backgroundthread.Start();      //开启后台线程
                    textBox1.ReadOnly = true;
                    button2.Enabled = true;
                    button1.Enabled = false;
                }
                catch (Exception ex)
                {
                    MessageBox.Show("过滤规则错误！"+ex.Message,"警告！");
                }
            }
            else
                MessageBox.Show("请选择网卡！","提示");
        }

        private void device_OnPacketArrival(object sender, CaptureEventArgs e)     //static
        {
//            Control.CheckForIllegalCrossThreadCalls = false;//跨线程操作
            lock(QueueLock)
            {
                PacketQueue[0].Add(e.Packet);
            }
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            if (packet is PacketDotNet.EthernetPacket)
            {
                var eth = ((PacketDotNet.EthernetPacket)packet);
                if (packet.PayloadPacket is PacketDotNet.ARPPacket)
                {
                    lock (QueueLock)
                    {
                        PacketQueue[1].Add(e.Packet);
                    }
                }
                var ip = PacketDotNet.IpPacket.GetEncapsulated(packet);
                if (ip != null)
                {
                    lock (QueueLock)
                    {
                        PacketQueue[2].Add(e.Packet);
                    }
                    var tcp = PacketDotNet.TcpPacket.GetEncapsulated(packet);
                    if (tcp != null)
                    {
                        lock (QueueLock)
                        {
                            PacketQueue[3].Add(e.Packet);
                        }
                        if (tcp.SourcePort == 80 || tcp.DestinationPort == 80)
                        {
                            lock (QueueLock)
                            {
                                PacketQueue[5].Add(e.Packet);
                            }
                        }
                    }
                    var udp = PacketDotNet.UdpPacket.GetEncapsulated(packet);
                    if (udp != null)
                    {
                        lock (QueueLock)
                        {
                            PacketQueue[4].Add(e.Packet);
                        }
                    }
                }
            }
        }

        private void Backgroundprocess()    //后台处理添加表格数据，统计
        {
            Control.CheckForIllegalCrossThreadCalls = false;//跨线程操作

            int _count = 0;
            listView1.Clear();
            this.listView1.GridLines = true;
            this.listView1.Clear();
            this.listView1.Columns.Add("序号", 60, HorizontalAlignment.Left);
            this.listView1.Columns.Add("时间", 120, HorizontalAlignment.Left);
            this.listView1.Columns.Add("源地址", 120, HorizontalAlignment.Left);
            this.listView1.Columns.Add("目的地址", 120, HorizontalAlignment.Left);
            this.listView1.Columns.Add("协议", 120, HorizontalAlignment.Left);
            this.listView1.Columns.Add("长度", 80, HorizontalAlignment.Left);
            while (true)
            {
                if (_count < PacketQueue[QueueNum].Count)
                {
                    RawCapture Addpacket;
                    lock (QueueLock)
                    {
                        Addpacket = PacketQueue[QueueNum][_count];
                    }
                    _count++;
                    ListViewItem item = new ListViewItem();


                    var time = Addpacket.Timeval.Date.ToLocalTime();
                    item.SubItems[0].Text = _count.ToString();
                    item.SubItems.Add(time.TimeOfDay.ToString());

                    string souce = "", destination = "", type = "";


                    var packet = PacketDotNet.Packet.ParsePacket(Addpacket.LinkLayerType, Addpacket.Data);
                    if (packet is PacketDotNet.EthernetPacket)
                    {
                        var eth = ((PacketDotNet.EthernetPacket)packet);

                        souce = eth.SourceHwAddress.ToString();
                        destination = eth.DestinationHwAddress.ToString();
                        if (destination == "ffffffffffff" || destination == "FFFFFFFFFFFF")
                            destination = "广播地址";
                        type = eth.Type.ToString();
                        var ip = PacketDotNet.IpPacket.GetEncapsulated(packet);
                        if (ip != null)
                        {
                            souce = ip.SourceAddress.ToString();
                            if (ip.SourceAddress.IsIPv6LinkLocal)
                                souce = "IPv6链接本地地址";
                            if (ip.SourceAddress.IsIPv6Multicast)
                                souce = "IPv6多路广播全局地址";
                            if (ip.SourceAddress.IsIPv6SiteLocal)
                                souce = "IPv6站点本地地址";
                            if (ip.SourceAddress.IsIPv6Teredo)
                                souce = "IPv6 Teredo地址";
                            destination = ip.DestinationAddress.ToString();
                            if (ip.SourceAddress.IsIPv6LinkLocal)
                                destination = "IPv6链接本地地址";
                            if (ip.DestinationAddress.IsIPv6Multicast)
                                destination = "IPv6多路广播全局地址";
                            if (ip.DestinationAddress.IsIPv6SiteLocal)
                                destination = "IPv6站点本地地址";
                            if (ip.DestinationAddress.IsIPv6Teredo)
                                destination = "IPv6 Teredo地址";
                            type = ip.Protocol.ToString();

                            var tcp = PacketDotNet.TcpPacket.GetEncapsulated(packet);
                            if (tcp != null)
                            {
                                if (tcp.DestinationPort == 80 || tcp.SourcePort == 80)
                                {
                                    type = "HTTP";
                                }
                                else if (tcp.DestinationPort == 443)
                                    type = "HTTPS";
                                else if (tcp.DestinationPort == 21)
                                    type = "FTP";
                                else
                                    type = "tcp" + "：" + tcp.SourcePort.ToString() + " to " + tcp.DestinationPort.ToString();
                            }

                            var udp = PacketDotNet.UdpPacket.GetEncapsulated(packet);
                            if (udp != null)
                            {
                                if (udp.DestinationPort == 53)
                                {
                                    type = "DNS";
                                }
                                else
                                    type = "udp" + "：" + udp.DestinationPort.ToString() + " to " + udp.DestinationPort.ToString();
                            }
                        }
                    }
                    item.SubItems.Add(souce);
                    item.SubItems.Add(destination);
                    item.SubItems.Add(type);
                    item.SubItems.Add(Addpacket.Data.Length.ToString());

                    this.listView1.Items.Add(item);
                    if(button2.Enabled)
                        item.EnsureVisible();
                    if(button2.Enabled)
                        label3.Text = "数据包统计： ETH：" + PacketQueue[0].Count + " ARP:" + PacketQueue[1].Count + " IP：" + PacketQueue[2].Count + " TCP:" + PacketQueue[3].Count + " UDP:" + PacketQueue[4].Count + " HTTP:" + PacketQueue[5].Count;
 
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Shutdown();
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            Shutdown();
            try
            {
                if (_Backgroundthread.IsAlive)
                {
                    _Backgroundthread.Abort();
                }
            }
            catch
            {
            }
        }

        private void button_Help_Click(object sender, EventArgs e)
        {
            Form2 frm = new Form2();
            frm.Show();
        }

        private void listView1_ItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e)
        {
//            MessageBox.Show(e.ItemIndex.ToString()+" "+PacketQueue[e.ItemIndex].ToString());
            RawCapture Select_Packet;
//            lock (QueueLock)
//            {
                Select_Packet = PacketQueue[QueueNum][e.ItemIndex];
//            }

            //RichTextBox:
            string[] Str = new string[Select_Packet.Data.Length / 16 + 1];
            richTextBox1.Text = "                          十六进制                              ASCII\r\n";//
//            Str[1] = "0000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    aaaaaaaaaaaaaaaa\n";
//            richTextBox1.Text = Str[0] + Str[1];
            for (int i = 0; i <= (Select_Packet.Data.Length - 1)/ 16;i++ )
            {
                Str[i] = i.ToString("X4");
                int j;
                for (j = 0; (j < 16) && (i * 16 + j < Select_Packet.Data.Length);j++ )
                {
                    if (j % 8 == 0)
                        Str[i] += "  ";
                    Str[i] += Select_Packet.Data[i * 16 + j].ToString("X2") + " ";
                }
                for (; j < 16; j++)
                {
                    if (j % 8 == 0)
                        Str[i] += "  ";
                    Str[i] += "   ";
                }
                Str[i] += "      ";
                for (j = 0; (j < 16) && (i * 16 + j < Select_Packet.Data.Length); j++)
                {
                    if (Select_Packet.Data[i * 16 + j] < 32 || Select_Packet.Data[i * 16 + j] > 126)
                        Str[i] += ".";
                    else
                    {
//                        if (Select_Packet.Data[i * 16 + j] == 34 || Select_Packet.Data[i * 16 + j] == 92)//如果遇到“/时加转移字符/
//                              Str[i] += Convert.ToChar(92);
                        Str[i] += Convert.ToChar(Select_Packet.Data[i * 16 + j]);
                    }
                }
            }

            for (int i = 0; i <= Select_Packet.Data.Length / 16; i++)
            {
                richTextBox1.Text += Str[i]+System.Environment.NewLine;
            }

            var packet = PacketDotNet.Packet.ParsePacket(Select_Packet.LinkLayerType, Select_Packet.Data);
/*
            //RichTextBox:
            richTextBox1.Text = packet.PrintHex();
 */
            //Treeview:
            treeView1.BeginUpdate();
            treeView1.Nodes.Clear();
            treeView1.Nodes.Add("Frame " + (e.ItemIndex+1).ToString()+":"+Select_Packet.Data.Length.ToString()+" bytes 被捕获");
            treeView1.Nodes[0].Nodes.Add("链路层类型："+Select_Packet.LinkLayerType.ToString());
            treeView1.Nodes[0].Nodes.Add("捕获时间：" + Select_Packet.Timeval.Date.ToLocalTime().DayOfWeek + " " + Select_Packet.Timeval.Date.ToLocalTime().TimeOfDay);
            treeView1.Nodes[0].Nodes.Add("数据帧长："+Select_Packet.Data.Length.ToString()+"bytes");

            
            if (packet is PacketDotNet.EthernetPacket)
            {
                var eth = ((PacketDotNet.EthernetPacket)packet);
                treeView1.Nodes.Add("以太网数据包：");
                treeView1.Nodes[1].Nodes.Add("源地址：" + eth.SourceHwAddress);
                treeView1.Nodes[1].Nodes.Add("目的地址：" + eth.DestinationHwAddress);
                treeView1.Nodes[1].Nodes.Add("上层协议" + eth.Type.ToString());

                if (packet.PayloadPacket is PacketDotNet.ARPPacket)
                {
                    var arp = ((PacketDotNet.ARPPacket)packet.PayloadPacket);
                    treeView1.Nodes.Add("ARP数据包：" + arp.ProtocolAddressLength + " bytes");
                    treeView1.Nodes[2].Nodes.Add("操作：" + arp.Operation);
                    treeView1.Nodes[2].Nodes.Add("协议地址类型：" + arp.ProtocolAddressType + " 协议地址长度：" + arp.ProtocolAddressLength + " bytes");
                    treeView1.Nodes[2].Nodes.Add("发送者硬件地址：" + arp.SenderHardwareAddress + " 发送者协议地址：" + arp.SenderProtocolAddress);
                    treeView1.Nodes[2].Nodes.Add("目标硬件地址：" + arp.TargetHardwareAddress + " 目标协议地址：" + arp.TargetProtocolAddress);
                }

                var ip = PacketDotNet.IpPacket.GetEncapsulated(packet);
                if (ip != null)
                {
                    treeView1.Nodes.Add("IP数据包：" + ip.TotalLength + " bytes");
                    treeView1.Nodes[2].Nodes.Add("版本：" + ip.Version + "  首部长度：" + ip.HeaderLength);
                    treeView1.Nodes[2].Nodes.Add("源地址：" + ip.SourceAddress);
                    treeView1.Nodes[2].Nodes.Add("目的地址：" + ip.DestinationAddress);
                  
                    if (ip is PacketDotNet.IPv4Packet)
                    {
                        var ipv4 = ((PacketDotNet.IPv4Packet)ip);
                        treeView1.Nodes[2].Nodes.Add("IPv4数据包：");
                        treeView1.Nodes[2].Nodes[3].Nodes.Add("分片标志：" + ipv4.FragmentFlags + " 片偏移：" + ipv4.FragmentOffset);
                        treeView1.Nodes[2].Nodes[3].Nodes.Add("标识：" + ipv4.Id);
                        treeView1.Nodes[2].Nodes[3].Nodes.Add("TOS服务类型：" + ipv4.TypeOfService);
                    }
                    if (ip is PacketDotNet.IPv6Packet)
                    {
                        var ipv6 = ((PacketDotNet.IPv6Packet)ip);
                        treeView1.Nodes[2].Nodes.Add("IPv6数据包：");
                        treeView1.Nodes[2].Nodes[3].Nodes.Add("流量类型：" + ipv6.TrafficClass);
                        treeView1.Nodes[2].Nodes[3].Nodes.Add("流标签：" + ipv6.FlowLabel);
                    }
                    treeView1.Nodes[2].Nodes.Add("协议类型：" + ip.Protocol);
                    treeView1.Nodes[2].Nodes.Add("TTL生存期：" + ip.TimeToLive);

                    if (ip.PayloadPacket is PacketDotNet.ICMPv4Packet)
                    {
                        var icmpv4 = (PacketDotNet.ICMPv4Packet)ip.PayloadPacket;
                        treeView1.Nodes.Add("ICMPv4数据包：");
                        treeView1.Nodes[3].Nodes.Add("类型编码：" + icmpv4.TypeCode);
                        treeView1.Nodes[3].Nodes.Add("序号：" + icmpv4.Sequence + "  ID:" + icmpv4.ID);
                    }
                    if (ip.PayloadPacket is PacketDotNet.ICMPv6Packet)
                    {
                        var icmpv6 = (PacketDotNet.ICMPv6Packet)ip.PayloadPacket;
                        treeView1.Nodes.Add("ICMPv6数据包：");
                        treeView1.Nodes[3].Nodes.Add("编码：" + icmpv6.Code);
                        treeView1.Nodes[3].Nodes.Add("类型：" + icmpv6.Type);
                    }
                    
                    var tcp = PacketDotNet.TcpPacket.GetEncapsulated(packet);
                    if (tcp != null)
                    {
                        treeView1.Nodes.Add("TCP数据包：");
                        treeView1.Nodes[3].Nodes.Add("源端口：" + tcp.SourcePort + " 目的端口：" + tcp.DestinationPort);
                        treeView1.Nodes[3].Nodes.Add("标志位：0x" + tcp.AllFlags.ToString("X2"));
                        treeView1.Nodes[3].Nodes[1].Nodes.Add("CWR：" + tcp.CWR);
                        treeView1.Nodes[3].Nodes[1].Nodes.Add("ECN：" + tcp.ECN);
                        treeView1.Nodes[3].Nodes[1].Nodes.Add("URG：" + tcp.Urg);
                        treeView1.Nodes[3].Nodes[1].Nodes.Add("ACK：" + tcp.Ack);
                        treeView1.Nodes[3].Nodes[1].Nodes.Add("PSH：" + tcp.Psh);
                        treeView1.Nodes[3].Nodes[1].Nodes.Add("RST：" + tcp.Rst);
                        treeView1.Nodes[3].Nodes[1].Nodes.Add("SYN：" + tcp.Syn);
                        treeView1.Nodes[3].Nodes[1].Nodes.Add("FIN：" + tcp.Fin);
                        treeView1.Nodes[3].Nodes.Add("序列号：" + tcp.SequenceNumber);
                        treeView1.Nodes[3].Nodes.Add("确认号：" + tcp.AcknowledgmentNumber);
                        treeView1.Nodes[3].Nodes.Add("窗口大小：" + tcp.WindowSize);
                        treeView1.Nodes[3].Nodes.Add("紧急指针：" + tcp.UrgentPointer);
                        treeView1.Nodes[3].Nodes.Add("数据偏移（首部长）：" + tcp.DataOffset);
                        
                        if ((ip is PacketDotNet.IPv4Packet) && Select_Packet.Data.Length > 54)
                        {
                            if (tcp.DestinationPort == 80 || tcp.SourcePort == 80)
                            {
                                treeView1.Nodes.Add("HTTP数据包：");
                            }
                            else if (tcp.DestinationPort == 443)
                            {
                                treeView1.Nodes.Add("HTTPS数据包：");
                            }
                            else
                            {
                                treeView1.Nodes.Add("数据：");
                            }
                            string tcpdata = "";
                            for (int i = 54; i < Select_Packet.Data.Length; i++)
                            {
                                if (Select_Packet.Data[i] < 32 || Select_Packet.Data[i] > 126)
                                    tcpdata += ".";
                                else
                                    tcpdata += Convert.ToChar(Select_Packet.Data[i]);
                                if (tcpdata.Length > 40)
                                {
                                    treeView1.Nodes[4].Nodes.Add(tcpdata);
                                    tcpdata = "";
                                }
                            }
                            treeView1.Nodes[4].Nodes.Add(tcpdata);
                        }

                        if ((ip is PacketDotNet.IPv6Packet) && Select_Packet.Data.Length > 74)
                        {
                            if (tcp.DestinationPort == 80 || tcp.SourcePort == 80)
                            {
                                treeView1.Nodes.Add("HTTP数据包：");
                            }
                            else if (tcp.DestinationPort == 443)
                            {
                                treeView1.Nodes.Add("HTTPS数据包：");
                            }
                            else
                            {
                                treeView1.Nodes.Add("数据：");
                            }
                            string tcpdata = "";
                            for (int i = 74; i < Select_Packet.Data.Length; i++)
                            {
                                if (Select_Packet.Data[i] < 32 || Select_Packet.Data[i] > 126)
                                    tcpdata += ".";
                                else
                                    tcpdata += Convert.ToChar(Select_Packet.Data[i]);
                                if (tcpdata.Length > 40)
                                {
                                    treeView1.Nodes[4].Nodes.Add(tcpdata);
                                    tcpdata = "";
                                }
                            }
                            treeView1.Nodes[4].Nodes.Add(tcpdata);
                        } 
                    }

                    var udp = PacketDotNet.UdpPacket.GetEncapsulated(packet);
                    if (udp != null)
                    {
                        treeView1.Nodes.Add("UDP数据包：");
                        treeView1.Nodes[3].Nodes.Add("源端口：" + udp.SourcePort + " 目的端口：" + udp.DestinationPort);
                        treeView1.Nodes[3].Nodes.Add("长度："+udp.Length);

                        if ((ip is PacketDotNet.IPv4Packet) && Select_Packet.Data.Length > 42)
                        {
                            if (udp.DestinationPort == 53)
                            {
                                treeView1.Nodes.Add("DNS数据包：");
                            }
                            else
                            {
                                treeView1.Nodes.Add("数据：");
                            }
                            string udpdata = "";
                            for (int i = 42; i < Select_Packet.Data.Length; i++)
                            {
                                if (Select_Packet.Data[i] < 32 || Select_Packet.Data[i] > 126)
                                    udpdata += ".";
                                else
                                    udpdata += Convert.ToChar(Select_Packet.Data[i]);
                                if (udpdata.Length > 40)
                                {
                                    treeView1.Nodes[4].Nodes.Add(udpdata);
                                    udpdata = "";
                                }
                            }
                            treeView1.Nodes[4].Nodes.Add(udpdata);
                        }
                        if ((ip is PacketDotNet.IPv6Packet) && Select_Packet.Data.Length > 62)
                        {
                            if (udp.DestinationPort == 53)
                            {
                                treeView1.Nodes.Add("DNS数据包：");
                            }
                            else
                            {
                                treeView1.Nodes.Add("数据：");
                            }
                            string udpdata = "";
                            for (int i = 62; i < Select_Packet.Data.Length; i++)
                            {
                                if (Select_Packet.Data[i] < 32 || Select_Packet.Data[i] > 126)
                                    udpdata += ".";
                                else
                                    udpdata += Convert.ToChar(Select_Packet.Data[i]);
                                if (udpdata.Length > 40)
                                {
                                    treeView1.Nodes[4].Nodes.Add(udpdata);
                                    udpdata = "";
                                }
                            }
                            treeView1.Nodes[4].Nodes.Add(udpdata);
                        }
                    }
                }
            }
            treeView1.EndUpdate();

        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (this.comboBox2.SelectedIndex >= 0)
            {
                try
                {
                    if (_Backgroundthread.IsAlive)
                    {
                        _Backgroundthread.Abort();
                    }
                }
                catch
                {
                }
                QueueNum = comboBox2.SelectedIndex;
                ThreadStart threadstart = new ThreadStart(Backgroundprocess);
                _Backgroundthread = new Thread(threadstart);
                _Backgroundthread.Start();      //开启后台线程
            }
        }
    }
}
