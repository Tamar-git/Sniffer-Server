using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.SqlClient;
using System.Linq;
using System.Net.Mail;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace SnifferServer
{
    class ClientRequestHandler
    {
        // SQL Server
        private SqlServer sql;

        // information about the client
        private TcpClient client;
        private string clientIP;
        private string email;

        // used for sending and reciving data
        private byte[] data;

        // the details that were sent
        private string name;
        private string password;

        // RSA and AES objects for encryption and decryption
        RsaCrypto rsa;
        AesCrypto aes;

        // Create a UnicodeEncoder to convert between byte array and string.
        UnicodeEncoding ByteConverter = new UnicodeEncoding();

        // requests' kinds
        const int signUpRequest = 1;
        const int signInRequest = 2;
        const int RegisterStatusResponse = 3;
        const int QuestionRequest = 4;
        const int EmailResponse = 5;
        const int CodeRequest = 6;
        const int QuestionResponse = 7;
        const int AnswerRequest = 8;
        const int PasswordRequest = 9;
        const int PasswordResponse = 10;
        const int PasswordChangeStatusResponse = 11;
        const int PublicKeyTransfer = 12;
        const int AesKeyTransfer = 13;

        /// <summary>
        /// constructor that gets a TCP Client, creates a new SqlServer object, a data array and starts reading the data stream
        /// </summary>
        /// <param name="client">TCP client</param>
        public ClientRequestHandler(TcpClient client)
        {
            this.client = client;

            // get the ip address of the client to register him with our client list
            clientIP = client.Client.RemoteEndPoint.ToString();

            // Creates a new SQL Server Object
            sql = new SqlServer();

            // Read data from the client async
            data = new byte[client.ReceiveBufferSize];



            /// test to the sniffer part
            NetworkStream ns;

            // we use lock to present multiple threads from using the networkstream object
            // this is likely to occur when the server is connected to multiple clients all of 
            // them trying to access to the networkstram at the same time.
            //lock (client.GetStream())
            //{
            //    ns = client.GetStream();
            //}

            // Send data to the client
            //byte[] bytesToSend = { 0, 1, 0, 1, 0, 1, 0, 1 };
            //ns.Write(bytesToSend, 0, bytesToSend.Length);
            //ns.Flush();


            //SendMessage(PublicKeyTransfer + "#" + rsa.GetServerPublicKey() + "#" + rsa.GetServerPublicKey().Length);

            // BeginRead will begin async read from the NetworkStream
            // This allows the server to remain responsive and continue accepting new connections from other clients
            // When reading complete control will be transfered to the ReviveMessage() function.
            client.GetStream().BeginRead(data,
                                          0,
                                          System.Convert.ToInt32(client.ReceiveBufferSize),
                                          ReceiveMessage,
                                          null);
        }
        /*
        // constructor that is used for entering a new game after finishing one
        // gets a TCP Client, creates a new SqlServer object, a data array and starts reading the data stream
        public ClientRequestHandler(TcpClient client, string username)
        {
            this.client = client;
            this.name = username;

            // get the ip address of the client to register him with our client list
            clientIP = client.Client.RemoteEndPoint.ToString();

            // Creates a new SQL Server Object
            sql = new SqlServer();

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
        */

        /// <summary>
        /// gets a string message and sends it to the client
        /// </summary>
        /// <param name="message">string to send to the client</param>
        public void SendMessage(byte[] message)
        {
            try
            {
                NetworkStream ns;

                // we use lock to prevent multiple threads from using the networkstream object
                // this is likely to occur when the server is connected to multiple clients all of 
                // them trying to access to the networkstram at the same time.
                lock (client.GetStream())
                {
                    ns = client.GetStream();
                }

                // MessageBox.Show("server sends " + message);

                // Send data to the client
                //byte[] bytesToSend = System.Text.Encoding.ASCII.GetBytes(message);
                //ns.Write(bytesToSend, 0, bytesToSend.Length);
                ns.Write(message, 0, message.Length);
                ns.Flush();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        /// <summary>
        /// gets a string message, encrypts it and sends it to the client
        /// </summary>
        /// <param name="message">string to encrypt and send to the client</param>
        public void SendEncryptedMessage(string message)
        {
            SendMessage(rsa.RSAEncrypt(ByteConverter.GetBytes(message)));
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
                if (rsa == null)
                {
                    //string key = Encoding.ASCII.GetString(data, 0, bytesRead).Split('#')[1];
                    string key = ByteConverter.GetString(data, 0, bytesRead).Split('#')[1];
                    // an Rsa crypto object is created
                    rsa = new RsaCrypto(key);
                    string messageToSend = PublicKeyTransfer + "#" + rsa.GetServerPublicKey() + "#" + rsa.GetServerPublicKey().Length;
                    SendMessage(ByteConverter.GetBytes(messageToSend));
                }
                else
                {
                    byte[] arrived = new byte[bytesRead];
                    Array.Copy(data, arrived, bytesRead);
                    byte[] bytesDecrypted = rsa.RSADecrypt(arrived);
                    string messageReceived = ByteConverter.GetString(bytesDecrypted);
                    //string messageReceived = System.Text.Encoding.ASCII.GetString(bytesDecrypted, 0, bytesDecrypted.Length);
                    string[] arrayReceived = messageReceived.Split('#');
                    int requestNumber = Convert.ToInt32(arrayReceived[0]);
                    string details = arrayReceived[1];
                    string[] detailsArray = details.Split('/');
                    // MessageBox.Show("server - order: " + order + " ,text: " + details);

                    string status = "ok";
                    if (requestNumber == signUpRequest)
                    {
                        // inserts to the SQL table
                        bool b = sql.Insert(detailsArray[0], detailsArray[1], detailsArray[2], detailsArray[3], detailsArray[4], 0);
                        if (!b)
                        {
                            status = "not ok";
                            SendEncryptedMessage(RegisterStatusResponse + "#" + status + "#" + status.Length);
                        }
                        else
                        {
                            name = detailsArray[0];
                            email = detailsArray[2];
                            string code = EmailVerification(email);
                            SendEncryptedMessage(EmailResponse + "#" + code + "#" + code.Length);

                            //opens a new object that handles the logs of the sniffer
                            SnifferLogs snifferLogs = new SnifferLogs(client, name);
                            return;
                        }
                    }
                    else if (requestNumber == signInRequest)
                    {
                        // checks if a player is in the table
                        int check = sql.IsExist(detailsArray[0], detailsArray[1]);
                        if (check == 0)
                            status = "not ok";
                        else
                            name = detailsArray[0];

                        Console.WriteLine(status + " 2");

                        if (check != 1)
                            //SendMessage(RegisterStatusResponse + "#" + status + "#" + status.Length);
                            SendEncryptedMessage(RegisterStatusResponse + "#" + status + "#" + status.Length);
                        else
                        {
                            string code = EmailVerification(sql.GetEmail(name));
                            SendEncryptedMessage(EmailResponse + "#" + code + "#" + code.Length);
                        }

                    }
                    else if (requestNumber == QuestionRequest)
                    {
                        string question = sql.GetQuestion(details);
                        name = details;
                        SendEncryptedMessage(QuestionResponse + "#" + question + "#" + question.Length);
                    }
                    else if (requestNumber == CodeRequest)
                    {
                        string originalCode = detailsArray[0].Trim();
                        string answer = detailsArray[1].Trim();

                        bool compare = originalCode.Equals(answer);
                        if (compare)
                        {
                            sql.ChangeEmailConfirmed(name);
                            SendEncryptedMessage(RegisterStatusResponse + "#" + "ok" + "#2");
                        }
                        else
                        {
                            string code = EmailVerification(sql.GetEmail(name));
                            SendEncryptedMessage(EmailResponse + "#" + code + "#" + code.Length);
                        }

                    }
                    else if (requestNumber == AnswerRequest)
                    {
                        bool checkAnswer = sql.GetAnswer(name).Equals(details);
                        if (checkAnswer)
                            //let the user invent a new password
                            SendEncryptedMessage(PasswordRequest + "##0");
                        else
                        {
                            string question = sql.GetQuestion(details);
                            name = details;
                            SendEncryptedMessage(QuestionResponse + "#" + question + "/" + "#" + question.Length);
                        }
                    }
                    else if (requestNumber == PasswordResponse)
                    {
                        bool b = sql.SetPassword(name, details);
                        string isChanged = "ok";
                        if (!b)
                            isChanged = "not ok";

                        SendEncryptedMessage(PasswordChangeStatusResponse + "#" + isChanged + "#" + isChanged.Length);
                    }
                    else if (requestNumber == PublicKeyTransfer)
                    {
                        // an Rsa crypto object is created
                        rsa = new RsaCrypto(details);
                        string messageToSend = PublicKeyTransfer + "#" + rsa.GetServerPublicKey() + "#" + rsa.GetServerPublicKey().Length;
                        SendMessage(ByteConverter.GetBytes(messageToSend));

                        /*string s = "hello";
                        string s2 = rsa.Encrypt(s);
                        Console.WriteLine(s2);
                        s2 = rsa.Decrypt(s2);
                        Console.WriteLine(s2);*/
                        //sendEncryptedMessage(rsa.Encrypt("hello"));

                    }
                    else if(requestNumber == AesKeyTransfer)
                    {
                        byte[] key = ByteConverter.GetBytes(details);
                        aes = new AesCrypto(key);
                        //Console.WriteLine("AES key {0}:", details);
                    }
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
                Console.WriteLine(ex.Message);
            }
        }

        /// <summary>
        /// gets an email and sends it a verification email with a code
        /// </summary>
        /// <param name="email">string of the client's email</param>
        /// <returns>the verification code that was sent to the client</returns>
        public static string EmailVerification(string email)
        {
            string code = RandomString(6);
            MailMessage mail = new MailMessage();
            SmtpClient SmtpServer = new SmtpClient("smtp.gmail.com");

            mail.From = new MailAddress("tamarg.project@gmail.com");
            mail.To.Add(email);
            mail.Subject = "Security Code";
            mail.Body = "Please insert the next code to the application: \n" + code;

            SmtpServer.UseDefaultCredentials = false;
            SmtpServer.Port = 587;
            SmtpServer.Credentials = new System.Net.NetworkCredential("tamarg.project@gmail.com", "tamagugupr20");
            SmtpServer.EnableSsl = true;

            SmtpServer.Send(mail);
            return code;
        }

        /// <summary>
        /// creates a random string according to the length it gets
        /// </summary>
        /// <param name="length">desirable code's length</param>
        /// <returns>the created code</returns>
        public static string RandomString(int length)
        {
            string s = "";
            Random rnd = new Random();
            int validChars = 0;

            while (validChars < length)
            {
                int randomInt = rnd.Next(48, 122);
                if ((randomInt < 58) || (randomInt > 64 && randomInt < 91) || (randomInt > 96))
                {
                    s += Convert.ToChar(randomInt);
                    validChars++;
                }
            }

            return s;
        }
    }
}