using System;
using System.Net.Sockets;

namespace SnifferServer
{
    class Program
    {
        const int portNo = 500;
        private const string ipAddress = "127.0.0.1";

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main(string[] args)
        {
            System.Net.IPAddress localAdd = System.Net.IPAddress.Parse(ipAddress);

            TcpListener listener = new TcpListener(localAdd, portNo);

            Console.WriteLine("Simple TCP Server");
            Console.WriteLine("Listening to ip {0} port: {1}", ipAddress, portNo);
            Console.WriteLine("Server is ready.");

            // Start listen to incoming connection requests
            listener.Start();
            
            // infinit loop.
            while (true)
            {
                // AcceptTcpClient - Blocking call
                // Execute will not continue until a connection is established

                // We create an instance of ClientRequestHandler so the server will be able to 
                // serve multiple client at the same time.
                ClientRequestHandler user = new ClientRequestHandler(listener.AcceptTcpClient());
            }
        }
    }
}
