using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SnifferServer
{
    class SqlServer
    {
        private string connectionString = @"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename=C:\Users\תמר\source\repos\SnifferServer\SnifferServer\Database1.mdf;Integrated Security=True"; // represents the location of the database
        private SqlConnection connection; // saves the open connection to the SQL Server database
        private SqlCommand cmd; // represents a Transact-SQL statement or stored procedure to execute against a SQL Server database
        private SqlDataReader rdr; // provides a way of reading the stream of rows from a SQL Server database

        /// <summary>
        /// constructor that creates a connection with the SQL Server and a new SqlCommand and connects it to the connection
        /// </summary>
        public SqlServer()
        {
            connection = new SqlConnection(connectionString);
            cmd = new SqlCommand();
            cmd.Connection = connection;
        }

        /// <summary>
        /// gets a name and a password and returns true if succeed to insert them to the database, else returns false
        /// </summary>
        /// <param name="name"></param>
        /// <param name="password"></param>
        /// <param name="email"></param>
        /// <param name="question"></param>
        /// <param name="answer"></param>
        /// <param name="isEmailConfirmed">boolean that indicates whether the user confirmed his email address</param>
        /// <returns>boolean that indicates the success of the method</returns>
        public bool Insert(string name, string password, string email, string question, string answer, int isEmailConfirmed)
        {
            //question = question.Substring(0, question.Length - 1);
            try
            {
                connection.Open();
                cmd.CommandText = "insert into Users values" +
                    "('" + name + "','" + password + "','" + email + "','" + @question + "','" + answer + "','" + isEmailConfirmed + "')";

                int numberOfChangedLines = cmd.ExecuteNonQuery();
                connection.Close();

                return numberOfChangedLines > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return false;
            }
        }


        /// <summary>
        /// gets a name and a password and returns true if these details exist in the database, else returns false
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns>int that indicates whether the user exists and confirmed his email</returns>
        public int IsExist(string username, string password)
        {
            connection.Open();

            cmd.CommandText = "select count(*) from Users where Username = '" + username + "' AND Password = '" + password + "' AND EmailConfirmed = '1'";
            int count = Convert.ToInt32(cmd.ExecuteScalar());


            if (count > 0)
            {
                connection.Close();
                return 2; // sign in successfully
            }

            cmd.CommandText = "select count(*) from Users where Username='" + username + "' AND Password = '" + password + "'";
            count = Convert.ToInt32(cmd.ExecuteScalar());
            connection.Close();
            if (count > 0)
                return 1; // needs to confirm email
            return 0; // details not valid

        }

        /// <summary>
        /// returns the client's email address
        /// </summary>
        /// <param name="username"></param>
        /// <returns>user's email</returns>
        public string GetEmail(string username)
        {
            connection.Open();

            cmd.CommandText = "select Email from Users where Username = '" + username + "'";
            // int count = Convert.ToInt32(cmd.ExecuteReader());
            string email = Convert.ToString(cmd.ExecuteScalar());
            connection.Close();

            return email;
        }

        /// <summary>
        /// returns the client's security question
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        public string GetQuestion(string username)
        {
            connection.Open();

            cmd.CommandText = "select Question from Users where Username = '" + username + "'";
            // int count = Convert.ToInt32(cmd.ExecuteReader());
            string question = Convert.ToString(cmd.ExecuteScalar());
            connection.Close();

            return question;
        }

        /// <summary>
        /// returns the client's answer to the security question
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        public string GetAnswer(string username)
        {
            connection.Open();

            cmd.CommandText = "select Answer from Users where Username = '" + username + "'";
            // int count = Convert.ToInt32(cmd.ExecuteReader());
            string answer = Convert.ToString(cmd.ExecuteScalar());
            connection.Close();

            return answer;
        }

        /// <summary>
        /// changes the password
        /// </summary>
        /// <param name="username"></param>
        /// <param name="newPassword"></param>
        /// <returns>whether the change was successessful</returns>
        public bool SetPassword(string username, string newPassword)
        {
            try
            {
                connection.Open();
                cmd.CommandText = "UPDATE Users SET Password = '" + newPassword + "' WHERE Username = '" + username + "'";

                int numberOfChangedLines = cmd.ExecuteNonQuery();
                connection.Close();

                return numberOfChangedLines > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return false;
            }
        }

        /// <summary>
        /// changes the username's email status when the client confirmes it
        /// </summary>
        /// <param name="username"></param>
        /// <returns>whether the change was successessful</returns>
        public bool ChangeEmailConfirmed(string username)
        {
            try
            {
                connection.Open();
                cmd.CommandText = "UPDATE Users SET EmailConfirmed = '1' WHERE Username = '" + username + "'";

                int numberOfChangedLines = cmd.ExecuteNonQuery();
                connection.Close();

                return numberOfChangedLines > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return false;
            }
        }

        /*
        public bool InsertQA(string name, string question, string answer)
        {
            try
            {
                connection.Open();
                cmd.CommandText = "UPDATE Users SET Question = '" + question + "', Answer = '" + answer + "' WHERE Username = '" + name + "'";


                int numberOfChangedLines = cmd.ExecuteNonQuery();
                connection.Close();

                return numberOfChangedLines > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return false;
            }
        }
        */

    }
}
