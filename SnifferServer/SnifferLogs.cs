using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.WinPcap;
using System.IO;

namespace SnifferServer
{
    class SnifferLogs
    {
        // information about the client
        private TcpClient client;
        private string clientIP;
        private string username;

        ICaptureDevice device;
        private PacketArrivalEventHandler arrivalEventHandler;
        // used for sending and reciving data
        private byte[] data;

        // requests' kinds
        const int packetDetailsResponse = 1;

        /// <summary>
        /// constructor that cretes a new object and start listening to messages
        /// </summary>
        /// <param name="client">TcpClient object</param>
        /// <param name="username">the client's username</param>
        public SnifferLogs(TcpClient client, string username)
        {
            this.client = client;
            this.username = username;

            // get the ip address of the client to register him with our client list
            clientIP = client.Client.RemoteEndPoint.ToString();

            // Read data from the client async
            data = new byte[client.ReceiveBufferSize];

            // BeginRead will begin async read from the NetworkStream
            // This allows the server to remain responsive and continue accepting new connections from other clients
            // When reading complete control will be transfered to the ReviveMessage() function.
            client.GetStream().BeginRead(data,
                                          0,
                                          System.Convert.ToInt32(client.ReceiveBufferSize),
                                          ReceiveMessage,
                                          null);

        }

        /// <summary>
        /// gets a string message and sends it to the client
        /// </summary>
        /// <param name="message">string to send to the client</param>
        public void SendMessage(string message)
        {
            try
            {
                NetworkStream ns;

                // we use lock to present multiple threads from using the networkstream object
                // this is likely to occur when the server is connected to multiple clients all of 
                // them trying to access to the networkstram at the same time.
                lock (client.GetStream())
                {
                    ns = client.GetStream();
                }

                // MessageBox.Show("server sends " + message);

                // Send data to the client
                byte[] bytesToSend = System.Text.Encoding.ASCII.GetBytes(message);
                ns.Write(bytesToSend, 0, bytesToSend.Length);
                ns.Flush();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        /// <summary>
        /// recursive method that recieves a message from the server and handles it according to the request or response number
        /// </summary>
        /// <param name="ar"></param>
        public void ReceiveMessage(IAsyncResult ar)
        {
            int bytesRead;

            try
            {
                lock (client.GetStream())
                {
                    // call EndRead to handle the end of an async read.
                    bytesRead = client.GetStream().EndRead(ar);
                }

                // MessageBox.Show("in receive server");
                string messageReceived = System.Text.Encoding.ASCII.GetString(data, 0, bytesRead);
                string[] arrayReceived = messageReceived.Split('#');
                int requestNumber = Convert.ToInt32(arrayReceived[0]);
                string details = arrayReceived[1];
                if (requestNumber == packetDetailsResponse)
                {
                    AddToLog(details);
                }
                lock (client.GetStream())
                {
                    // continue reading from the client
                    client.GetStream().BeginRead(data, 0, System.Convert.ToInt32(client.ReceiveBufferSize), ReceiveMessage, null);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("catch recieve");
            }
        }

        /// <summary>
        /// adds the data in the message to the client's log
        /// </summary>
        /// <param name="data">information about the packet</param>
        public void AddToLog(string data)
        {

            try
            {
                //Pass the filepath and filename to the StreamWriter Constructor
                StreamWriter sw = new StreamWriter(GetFilePath(), true);
                //Write a line of text
                sw.WriteLine(data);

                //Close the file
                sw.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: " + e.Message);
            }

        }

        /// <summary>
        /// builds a log file path according to the date and the client's username
        /// </summary>
        /// <returns>string that represents the path</returns>
        public string GetFilePath()
        {
            string s = "LOG_";
            string date = DateTime.Today.ToLocalTime().ToString("yyyyMMdd");
            string name = username;
            s += date + "_" + name + ".csv";
            return @"C:\Users\תמר\source\repos\SnifferServer\SnifferServer\" + s;
        }

        public void Connection(TcpPacket packet)
        {
            IpPacket ipPacket = (IpPacket)packet.ParentPacket;
            string m_srcIp = ipPacket.SourceAddress.ToString();
            string m_dstIp = ipPacket.DestinationAddress.ToString();
            int m_srcPort = (ushort)packet.SourcePort;
            int m_dstPort = (ushort)packet.DestinationPort;
            _ = packet.Bytes;
        }

        /*private void OnPacketArrival(object sender, SharpPcap.CaptureEventArgs e)
        {
            var rawPacket = e.Packet;
            var etherPacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var ipPacket = (IpPacket)etherPacket.PayloadPacket;
            var tcpPacket = (TcpPacket)etherPacket.PayloadPacket.PayloadPacket;
            var payload = etherPacket.PayloadPacket.PayloadPacket.PayloadData;
            var toServer = tcpPacket.DestinationPort == 20100;

            if (payload.Length < 1)
                return;

            if (toServer && _srcPort == 0)
            {
                _srcPort = tcpPacket.SourcePort;
                _srcIP = ipPacket.SourceAddress;
                _destIP = ipPacket.DestinationAddress;
                var ether = (EthernetPacket)etherPacket;

                _destPhysical = ether.DestinationHwAddress;
                _srcPhsyical = ether.SourceHwAddress;
            }

            if (toServer && !put)
            {
                put = true;
                Console.WriteLine(etherPacket);
            }
            Gunz2Packet packet = new Gunz2Packet(payload, _cryptKey);
            if (packet.pktID == 0xC1C)
            {
                Array.Clear(_cryptKey, 0, _cryptKey.Length);
                var index = 33;
                var cryptKeySeed = BitConverter.ToUInt32(packet.data, index);

                MakeCryptKey(cryptKeySeed);
                var writer = new StreamWriter("gunz2shark.log", true);
                writer.WriteLine("[KEY]");
                Program.PacketLog(_cryptKey, 0, _cryptKey.Length, writer);
                writer.WriteLine("[END KEY]\n");
                writer.Close();
            }

            if (packet.pktID == 0xDFC)
            {
                SendSupplyBoxOpen();
            }

            var cmd = _commands.Find(x => x.GetOpcode() == packet.pktID);

            if (cmd != null && !packet.flags.unkFlag3)
            {

                File.WriteAllBytes(cmd.GetOpcode() + ".bin", packet.data);
                var writer = new StreamWriter("gunz2shark.log", true);

                var output = string.Format("[{0}] | {1} | {2}({2:X}) | Parameters ->", toServer ? "C2S" : "S2C", cmd.Desc, cmd.GetOpcode());

                if (cmd.Params != null)
                {
                    foreach (var param in cmd.Params)
                        output += string.Format("{0} -> ", param.Type);
                }

                output += "end";

                Console.WriteLine(output);
                writer.WriteLine(output);

                Program.PacketLog(packet.data, 0, (int)packet.data.Length, writer);
                writer.Close();
            }
            else
                Console.WriteLine("Unknown command: {0}", packet.pktID);
        }*/
        /* private void device_OnPacketArrival(object sender, SharpPcap.CaptureEventArgs e)
                {
                    if (e.Packet.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
                    {
                        PacketDotNet.Packet packet;

                        long TotalPacketSize = e.Packet.Data.Length;
                        BytesRead += TotalPacketSize;
                        ++PacketsSeen;

                        if ((PacketsSeen > 0) && ((PacketsSeen % 10000) == 0))
                        {
                            DebugLog.ConsoleWindow.SelectedIndex = DebugLog.ConsoleWindow.Items.Count - 1;
                            int Progress = (int)((float)BytesRead / (float)CaptureFileSize * 100);
                            ProgressBar.Value = Progress;

                            Application.DoEvents();
                        }

                        try
                        {
                            packet = PacketDotNet.Packet.ParsePacket(e.Packet);
                        }
                        catch
                        {
                            return;
                        }

                        var ethernetPacket = (PacketDotNet.EthernetPacket)packet;

                        var udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(packet);

                        if (udpPacket != null)
                        {
                            var ipPacket = (PacketDotNet.IpPacket)udpPacket.ParentPacket;
                            System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                            System.Net.IPAddress dstIp = ipPacket.DestinationAddress;

                            byte[] Payload = udpPacket.PayloadData;

                            Int32 l = udpPacket.Length - udpPacket.Header.GetLength(0);

                            if (l > 0)
                            {
                                Array.Resize(ref Payload, l);

                                StreamProcessor.ProcessPacket(srcIp, dstIp, udpPacket.SourcePort, udpPacket.DestinationPort, Payload, packet.Timeval.Date);
                            }
                        }
                    }
                }
             */
    }
}
