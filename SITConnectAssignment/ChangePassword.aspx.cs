using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace SITConnectAssignment
{
    public partial class ChangePassword : System.Web.UI.Page
    {

        string MYDBConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["SITConnectDB"].ConnectionString;
        string finalHash;
        string salt;

        protected void Page_Load(object sender, EventArgs e)
        {
            if (Session["UserID"] != null && Session["AuthToken"] != null && Request.Cookies["AuthToken"] != null)
            {
                if (!Session["AuthToken"].ToString().Equals(Request.Cookies["AuthToken"].Value))
                {
                    Response.Redirect("Login.aspx", false);
                }
                else if (DateTime.Now < getDateTime())
                {
                    Response.Redirect("Details.aspx", false);
                } else
                {
                    if (Session["NewPass"] != null)
                    {
                        ScriptManager.RegisterClientScriptBlock(this, this.GetType(), "alertMessage", "alert('Your account password age has exceeded 15 minutes, please change your password')", true);
                        Session.Remove("NewPass");

                    }
                }


            }
        }

        protected void btn_submit_Click(object sender, EventArgs e)
        {
            if (Session["UserID"] != null)
            {
                if (ValidateCaptcha() && checkInputs())
                {

                    string email = Session["UserId"].ToString();

                    //Check if in PreviousPass
                    bool newPass = true;

                    List<PreviousPass> previousPasses = retrievePreviousPass(email);
                    foreach (PreviousPass passObj in previousPasses)
                    {
                        SHA512Managed hashing = new SHA512Managed();

                        //Get the current input password + previous salts, hash them, and compare with previous hash
                        string pwdWithSalt = tb_password.Text + passObj.PasswordSalt;
                        byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                        string previousPassHash = Convert.ToBase64String(hashWithSalt);

                        //if passwordInput+previousSalt = previousHash: Same password
                        if (previousPassHash.Equals(passObj.PasswordHash))
                        {
                            newPass = false;
                            break;
                        }
                    }

                    if (newPass)
                    {

                        //Generate random "salt"
                        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                        byte[] saltByte = new byte[8];

                        //Fills array of bytes with a cryptographically strong sequence of random values.
                        rng.GetBytes(saltByte);
                        salt = Convert.ToBase64String(saltByte);  //Salt value to be stored

                        SHA512Managed hashing = new SHA512Managed();

                        string pwdWithSalt = tb_password.Text + salt;
                        byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                        finalHash = Convert.ToBase64String(hashWithSalt); //Hash with salt value to be stored

                        updateAccount();

                        //Session.Remove("UserID");

                        //if (Request.Cookies["ASP.NET_SessionId"] != null)
                        //{
                        //    Response.Cookies["ASP.NET_SessionId"].Value = string.Empty;
                        //    Response.Cookies["ASP.NET_SessionId"].Expires = DateTime.Now.AddMonths(-20);
                        //}
                        //if (Request.Cookies["AuthToken"] != null)
                        //{
                        //    Response.Cookies["AuthToken"].Value = string.Empty;
                        //    Response.Cookies["AuthToken"].Expires = DateTime.Now.AddMonths(-20);
                        //}

                        //Response.Redirect("Login.aspx", false);
                        Response.Redirect("Details.aspx", false);
                    } else
                    {
                        lbl_pwdchecker.Text = "Password Input has been used in the previous 3 passwords! please make a new password!";
                    }

                }
            } else
            {
                ScriptManager.RegisterClientScriptBlock(this, this.GetType(), "alertMessage", "Session has expired, please login again.", true);
                Response.Redirect("Login.aspx", false);
            }


        }

        public class PreviousPass
        {
            public int UserId { get; set; }
            public string PasswordHash { get; set; }
            public string PasswordSalt { get; set; }
        }

        public List<PreviousPass> retrievePreviousPass(string email)
        {
            List<PreviousPass> result = new List<PreviousPass>();
            int userId = 0;


            SqlConnection connection = new SqlConnection(MYDBConnectionString);

            string sql = "SELECT Id, PasswordHash, PasswordSalt FROM Account WHERE Email = @email";
            SqlCommand cmd = new SqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@email", email);

            try
            {
                connection.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        PreviousPass passDetail = new PreviousPass();
                        passDetail.UserId = int.Parse(reader[0].ToString());
                        passDetail.PasswordHash = reader[1].ToString();
                        passDetail.PasswordSalt = reader[2].ToString();
                        result.Add(passDetail);

                        userId = int.Parse(reader[0].ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }



            string sql2 = "SELECT TOP 2 * FROM PreviousPass WHERE UserId = @userId ORDER BY Id DESC ;";
            SqlCommand cmd2 = new SqlCommand(sql2, connection);
            cmd2.Parameters.AddWithValue("@userId", userId);

            try
            {
                connection.Open();
                using (SqlDataReader reader = cmd2.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        PreviousPass passDetail = new PreviousPass();
                        passDetail.UserId = int.Parse(reader["UserId"].ToString());
                        passDetail.PasswordHash = reader["PasswordHash"].ToString();
                        passDetail.PasswordSalt = reader["PasswordSalt"].ToString();
                        result.Add(passDetail);

                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }


            return result;

        }


        public void updateAccount()
        {

            SqlConnection connection = new SqlConnection(MYDBConnectionString);

            //Retrieve current PasswordHash and Salt
            string sql = "SELECT Id, PasswordHash, PasswordSalt FROM Account WHERE lower(Email) = @Email";
            SqlCommand cmd = new SqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Email", Session["UserID"].ToString().ToLower());

            string userId = string.Empty;
            string passwordHash = string.Empty;
            string passwordSalt = string.Empty;
            try
            {
                connection.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        userId = reader["Id"].ToString();
                        passwordHash = reader["PasswordHash"].ToString();
                        passwordSalt = reader["PasswordSalt"].ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }

            //And store them in PreviousPass

            sql = "INSERT INTO PreviousPass VALUES(@UserId, @PasswordHash, @PasswordSalt)";
            cmd = new SqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@UserId", userId);
            cmd.Parameters.AddWithValue("@PasswordHash", passwordHash);
            cmd.Parameters.AddWithValue("@PasswordSalt", passwordSalt);

            try
            {
                connection.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }

            //Update Account Value with new password!

            int s = 0;
            sql = "UPDATE Account SET PasswordHash = @PasswordHash, PasswordSalt = @PasswordSalt, PasswordChangeTime = getdate() WHERE lower(Email) = @Email";
            cmd = new SqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@PasswordHash", finalHash);
            cmd.Parameters.AddWithValue("@PasswordSalt", salt);
            cmd.Parameters.AddWithValue("@Email", Session["UserID"].ToString().ToLower());

            try
            {
                connection.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["Id"] != null)
                        {
                            if (reader["Id"] != DBNull.Value)
                            {
                                s = int.Parse(reader["Id"].ToString());
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


        protected Boolean checkInputs()
        {
            Boolean valid = true;
            List<string> errorList = new List<string>();


            if (!Regex.IsMatch(tb_password.Text, @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@!%*?&]{8,}$"))
            {
                valid = false;
                lbl_pwdchecker.Text = "Invalid Password Input!";
                errorList.Add("• Password value is invalid!");
            } else if (tb_password.Text != tb_cfmPassword.Text)
            {
                valid = false;
                lbl_pwdchecker.Text = "Password and Confirm Password does not match!";
                errorList.Add("• Password and Confirm Password does not match!");

            }
            else { lbl_pwdchecker.Text = ""; }


            string errorText = "Error List: \n" + String.Join("\n", errorList);
            lbl_pwdchecker.Text = errorText;

            return valid;
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