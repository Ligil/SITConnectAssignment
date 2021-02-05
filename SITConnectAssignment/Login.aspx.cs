using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

using System.Security.Cryptography;
using System.Text;
using System.Data;
using System.Data.SqlClient;

using System.Net;
using System.IO;
using System.Web.Script.Serialization;
using System.Web.Services;


namespace SITConnectAssignment
{
    public partial class Login : System.Web.UI.Page
    {
        string MYDBConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["SITConnectDB"].ConnectionString;
        protected void Page_Load(object sender, EventArgs e)
        {
        }

        protected void btn_submit_Click(object sender, EventArgs e)
        {
            if (ValidateCaptcha())
            {
                string email = tb_email.Text.ToString().Trim();
                string pwd = tb_password.Text.ToString().Trim();
                SHA512Managed hashing = new SHA512Managed();
                string dbHash = getDBHash(email);
                string dbSalt = getDBSalt(email);

                int attempts = getDBLockoutCount(email);
                DateTime lockoutTime = getDBLockoutTime(email);

                if (DateTime.Now > lockoutTime && attempts >= 3)
                {
                    updateDBLockoutCount(email, 0);
                }

                try
                {
                    if (dbSalt != null && dbSalt.Length > 0 && dbHash != null && dbHash.Length > 0)
                    {
                        string pwdWithSalt = pwd + dbSalt;
                        byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                        string userHash = Convert.ToBase64String(hashWithSalt);
                        if (userHash.Equals(dbHash))
                        {
                            if (DateTime.Now < lockoutTime && attempts >= 3)
                            {
                                lbl_errormsg.Text = "Your account has been locked out. It will be unlocked at " + lockoutTime.ToString();
                            } else
                            {
                                Session["UserID"] = email;

                                //Create a new GUID and save into the session
                                string guid = Guid.NewGuid().ToString();
                                Session["AuthToken"] = guid;
                                Response.Cookies.Add(new HttpCookie("AuthToken", guid));

                                updateDBLockoutCount(email, 0);

                                //If over 15 minutes since last change password, force change
                                if (DateTime.Now > getDateTime().AddMinutes(15))
                                {
                                    Session["NewPass"] = true;
                                    Response.Redirect("ChangePassword.aspx", false);
                                } else
                                {
                                    Response.Redirect("Details.aspx", false);
                                }
                            }
                        }
                        else
                        {
                            updateDBLockoutCount(email, attempts + 1);
                            int remainingAttempts = 2 - attempts;
                            if (remainingAttempts <= 0)
                            {
                                lbl_errormsg.Text = "Account has been locked out! It will be unlocked in a minute";
                            }
                            else if (remainingAttempts == 1)
                            {
                                lbl_errormsg.Text = "Email or password is not valid. Please try again. 1 more attempt before account lockout";
                            } else
                            {
                                lbl_errormsg.Text = "Email or password is not valid. Please try again.";
                            }
                        }
                    }
                    else
                    {
                        lbl_errormsg.Text = "Email or password is not valid. Please try again.";
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception(ex.ToString());
                }
                finally { }
            } else
            {
                lbl_errormsg.Text = "Hi robot! :D";
            }

        }

        protected string getDBHash(string email)
        {
            string h = null;
            SqlConnection connection = new SqlConnection(MYDBConnectionString);
            string sql = "SELECT PasswordHash FROM Account WHERE lower(Email)=@email";
            SqlCommand command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@email", email.ToLower());
            try
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {

                    while (reader.Read())
                    {
                        if (reader["PasswordHash"] != null)
                        {
                            if (reader["PasswordHash"] != DBNull.Value)
                            {
                                h = reader["PasswordHash"].ToString();
                            }
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }
            return h;
        }

        protected string getDBSalt(string email)
        {
            string s = null;
            SqlConnection connection = new SqlConnection(MYDBConnectionString);
            string sql = "SELECT PasswordSalt FROM Account WHERE lower(Email)=@email";
            SqlCommand command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@email", email.ToLower());
            try
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["PasswordSalt"] != null)
                        {
                            if (reader["PasswordSalt"] != DBNull.Value)
                            {
                                s = reader["PasswordSalt"].ToString();
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }
            return s;
        }

        protected int getDBLockoutCount(string email)
        {
            int s = 0;
            SqlConnection connection = new SqlConnection(MYDBConnectionString);
            string sql = "SELECT LockoutCount FROM Account WHERE lower(Email)=@email";
            SqlCommand command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@email", email.ToLower());
            try
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["LockoutCount"] != null)
                        {
                            if (reader["LockoutCount"] != DBNull.Value)
                            {
                                s = int.Parse(reader["LockoutCount"].ToString());
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }
            return s;
        }

        protected DateTime getDBLockoutTime(string email)
        {
            DateTime s = new DateTime();
            SqlConnection connection = new SqlConnection(MYDBConnectionString);
            string sql = "SELECT LockoutTime FROM Account WHERE lower(Email)=@email";
            SqlCommand command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@email", email.ToLower());
            try
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["LockoutTime"] != null)
                        {
                            if (reader["LockoutTime"] != DBNull.Value)
                            {
                                s = DateTime.Parse(reader["LockoutTime"].ToString());
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }
            return s;
        }

        public DateTime getDateTime()
        {
            SqlConnection connection = new SqlConnection(MYDBConnectionString);

            //Retrieve current PasswordHash and Salt
            string sql = "SELECT PasswordChangeTime FROM Account WHERE lower(Email) = @Email";
            SqlCommand cmd = new SqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Email", Session["UserID"].ToString().ToLower());

            DateTime PassChangeTime = DateTime.Now;
            try
            {
                connection.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        PassChangeTime = DateTime.Parse(reader["PasswordChangeTime"].ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }
            return PassChangeTime;
        }

        protected int updateDBLockoutCount(string email, int number)
        {
            if (number >= 3)
            {
                int s = 0;
                SqlConnection connection = new SqlConnection(MYDBConnectionString);
                string sql = "UPDATE Account SET LockoutCount=@count, LockoutTime=@time WHERE lower(Email)=@email";
                SqlCommand command = new SqlCommand(sql, connection);
                command.Parameters.AddWithValue("@count", number);
                command.Parameters.AddWithValue("@email", email.ToLower());
                command.Parameters.AddWithValue("@time", DateTime.Now.AddMinutes(1));
                try
                {
                    connection.Open();
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            if (reader["LockoutCount"] != null)
                            {
                                if (reader["LockoutCount"] != DBNull.Value)
                                {
                                    s = int.Parse(reader["LockoutCount"].ToString());
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception(ex.ToString());
                }
                finally { connection.Close(); }
                return s;
            } else
            {
                int s = 0;
                SqlConnection connection = new SqlConnection(MYDBConnectionString);
                string sql = "UPDATE Account SET LockoutCount=@count WHERE lower(Email)=@email";
                SqlCommand command = new SqlCommand(sql, connection);
                command.Parameters.AddWithValue("@count", number);
                command.Parameters.AddWithValue("@email", email.ToLower());
                try
                {
                    connection.Open();
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            if (reader["LockoutCount"] != null)
                            {
                                if (reader["LockoutCount"] != DBNull.Value)
                                {
                                    s = int.Parse(reader["LockoutCount"].ToString());
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception(ex.ToString());
                }
                finally { connection.Close(); }
                return s;
            }

        }

        protected void tb_password_TextChanged(object sender, EventArgs e)
        {
            lbl_errormsg.Text = "";
        }


        public class MyObject
        {
            public string success { get; set; }
            public List<string> ErrorMessage { get; set; }
        }

        public bool ValidateCaptcha()
        {
            bool result = true;

            //When user submits the recaptcha form, the user gets a response POST parameter.
            //captchaResponse consist of the user click pattern. Behaviour analytics! AI :)
            string captchaResponse = Request.Form["g-recaptcha-response"];

            //To send a GET request to Goole along with the response and Secret key.
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create
                ("https://www.google.com/recaptcha/api/siteverify?secret=6LfNt-sZAAAAADGCq7E_k-N3geEpLuUG3znCzege &response=" + captchaResponse);

            try
            {
                //Codes to receive the Response in JSON format from Google Server
                using (WebResponse wResponse = req.GetResponse())
                {
                    using (StreamReader readStream = new StreamReader(wResponse.GetResponseStream()))
                    {
                        //The response in JSON format
                        string jsonResponse = readStream.ReadToEnd();

                        //To show the JSON response string for learning purpose (Tested, kept getting 0.9)
                        //lbl_gScore.Text = jsonResponse.ToString();

                        JavaScriptSerializer js = new JavaScriptSerializer();

                        //Create jsonObject to handle the response e.g success or Error
                        //Deserialize Json
                        MyObject jsonObject = js.Deserialize<MyObject>(jsonResponse);

                        //Convert the string "False" to bool false or "True" to bool true
                        result = Convert.ToBoolean(jsonObject.success);
                    }
                }

                return result;
            }
            catch (WebException ex)
            {
                throw ex;
            }
        }


    }
}