using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SnifferServer
{
    class Communication
    {
        // information about the client
        private TcpClient client;
        private string clientIP;

        // used for sending and reciving data
        private byte[] data;

        // constructor that gets a TCP Client, creates a new SqlServer object, a data array and starts reading the data stream
        public Communication(TcpClient client)
        {
            this.client = client;

            // get the ip address of the client to register him with our client list
            clientIP = client.Client.RemoteEndPoint.ToString();

            // Read data from the client async
            data = new byte[client.ReceiveBufferSize];

            // BeginRead will begin async read from the NetworkStream
            // This allows the server to remain responsive and continue accepting new connections from other clients
            // When reading complete control will be transfered to the ReviveMessage() function.
            //client.GetStream().BeginRead(data,
            //                              0,
            //                              System.Convert.ToInt32(client.ReceiveBufferSize),
            //                              ReceiveMessage,
            //                              null);
        }

        // gets a string message and sends it to the client
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

        //EventHandler messageReceived = new EventHandler();

        /// <summary>
        /// recursive method that recieves a message from the server and returns it to the class
        /// </summary>
        /// <param name="ar"></param>
        /// <returns></returns>
        public string ReceiveMessage(IAsyncResult ar)
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
                
                string[] detailsArray = details.Split('/');

                lock (client.GetStream())
                {
                    // continue reading from the client
                    //client.GetStream().BeginRead(data, 0, System.Convert.ToInt32(client.ReceiveBufferSize), ReceiveMessage, null);
                }
                return details;
            }

            catch (Exception ex)
            {
                Console.WriteLine("catch recieve");
                return "catch recieve";
            }
        }
    }
}
