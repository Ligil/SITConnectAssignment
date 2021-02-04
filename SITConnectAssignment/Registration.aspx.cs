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
using System.Text.RegularExpressions;

using System.Net;
using System.IO;
using System.Web.Script.Serialization;
using System.Web.Services;
using System.Globalization;

namespace SITConnectAssignment
{
    public partial class Registration : System.Web.UI.Page
    {

        string MYDBConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["SITConnectDB"].ConnectionString;
        string finalHash;
        string salt;
        byte[] IV;
        byte[] Key;

        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btn_submit_Click(object sender, EventArgs e)
        {
            if (ValidateCaptcha() && checkInputs())
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

                RijndaelManaged cipher = new RijndaelManaged();
                cipher.GenerateKey();
                Key = cipher.Key;
                IV = cipher.IV;

                createAccount();

                Response.Redirect("Login.aspx", false);
            }
        }

        protected Boolean checkInputs()
        {
            Boolean valid = true;
            List<string> errorList = new List<string>();

            if (tb_firstname.Text.Length < 1)
            {
                valid = false;
                lbl_firstnamechecker.Text = "First name has no value!";
                errorList.Add("• First name no value!");
            } 
            else { lbl_firstnamechecker.Text = ""; }

            if (tb_lastname.Text.Length < 1)
            {
                valid = false;
                lbl_lastnamechecker.Text = "Last name has no value!";
                errorList.Add("• Last name no value!");
            } 
            else { lbl_lastnamechecker.Text = ""; }

            if (tb_creditcardNum.Text.Length < 10)
            {
                valid = false;
                lbl_numberchecker.Text = "Credit Card number must be a valid number! (at least 10 digits)";
                errorList.Add("• Credit card num invalid value!");
            }
            else { lbl_numberchecker.Text = ""; }

            if (!Regex.IsMatch(tb_creditcardExp.Text, @"^[\d]{4}-[\d]{2}-[\d]{2}$"))
            {
                valid = false;
                lbl_expirychecker.Text = "Credit Card Expiry Date has invalid value!";
                errorList.Add("• Credit card expiry date invalid value!");
            } else
            {
                DateTime result = DateTime.ParseExact(tb_creditcardExp.Text, "yyyy-MM-dd", CultureInfo.InvariantCulture);
                if (result < DateTime.Now)
                {
                    valid = false;
                    lbl_expirychecker.Text = "Credit Card is expied?";
                    errorList.Add("• Credit card expiry date already over!");
                }
                else { lbl_expirychecker.Text = ""; }
            }


            if (!Regex.IsMatch(tb_creditcardCVV.Text , @"^[\d]{3,4}$"))
            {
                valid = false;
                lbl_cvvchecker.Text = "Invalid CVV value!";
                errorList.Add("• Credit card CVV value is invalid!");
            } 
            else { lbl_cvvchecker.Text = ""; }

            if (!Regex.IsMatch(tb_email.Text, @"^\w+[\+\.\w-]*@([\w-]+\.)*\w+[\w-]*\.([a-z]{2,4}|\d+)$", RegexOptions.IgnoreCase))
            {
                valid = false;
                lbl_emailchecker.Text = "Email has an invalid value!";
                errorList.Add("• Email value is invalid!");
            } else{
                DataSet dset = new DataSet();
                DataSet profileDset = new DataSet();
                SqlConnection conn = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["SITConnectDB"].ToString());
                using (conn)
                {
                    conn.Open();
                    SqlDataAdapter adapter = new SqlDataAdapter();

                    SqlCommand cmd = new SqlCommand("SELECT Id, Firstname, Lastname, CCnumber, CCexpdate, CCcvv, Email, PasswordHash, PasswordSalt, Dateofbirth FROM Account WHERE lower(Email) = @Email", conn);
                    cmd.Parameters.AddWithValue("@Email", tb_email.Text.ToLower());
                    cmd.CommandType = CommandType.Text;
                    adapter.SelectCommand = cmd;
                    adapter.Fill(dset);

                }
                
                if (dset.Tables[0].Rows.Count > 0)
                {
                    valid = false;
                    lbl_emailchecker.Text = "Email is already a registered account!";
                    errorList.Add("• Email value is already registered!");
                }
                else { lbl_emailchecker.Text = ""; }

            }

            if (!Regex.IsMatch(tb_password.Text, @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@!%*?&]{8,}$"))
            {
                valid = false;
                lbl_pwdchecker.Text = "Invalid Password Input!";
                errorList.Add("• Password value is invalid!");
            }
            else { lbl_pwdchecker.Text = ""; }


            if (!Regex.IsMatch(tb_dob.Text, @"^[\d]{4}-[\d]{2}-[\d]{2}$"))
            {
                valid = false;
                lbl_dobchecker.Text = "Date of birth is an Invalid Value!";
                errorList.Add("• Date of birth invalid value!");
            }
            else
            {
                DateTime result = DateTime.ParseExact(tb_dob.Text, "yyyy-MM-dd", CultureInfo.InvariantCulture);
                if (result > DateTime.Now)
                {
                    valid = false;
                    lbl_dobchecker.Text = "Date of birth should be before current date!";
                    errorList.Add("• Date of birth cannot be before current date!");
                }
                else { lbl_dobchecker.Text = ""; }
            }


            string errorText = "Error List: \n" + String.Join("\n", errorList);
            lbl_submitchecker.Text = errorText;

            return valid;
        }

        public void createAccount()
        {
            try
            {
                using (SqlConnection con = new SqlConnection(MYDBConnectionString))
                {
                    using (SqlCommand cmd = new SqlCommand("INSERT INTO Account VALUES(@Firstname, @Lastname, @CCnumber, @CCexpdate, @CCcvv, @Email, @PasswordHash, @PasswordSalt, @Dateofbirth, @IV, @Key, 0)"))
                    {
                        using (SqlDataAdapter sda = new SqlDataAdapter())
                        {
                            cmd.CommandType = CommandType.Text;

                            cmd.Parameters.AddWithValue("@Firstname", tb_firstname.Text.Trim());
                            cmd.Parameters.AddWithValue("@Lastname", tb_lastname.Text.Trim());
                            cmd.Parameters.AddWithValue("@CCnumber", Convert.ToBase64String(encryptData(tb_creditcardNum.Text.Trim())));
                            cmd.Parameters.AddWithValue("@CCexpdate", tb_creditcardExp.Text.Trim());
                            cmd.Parameters.AddWithValue("@CCcvv", tb_creditcardCVV.Text.Trim());
                            cmd.Parameters.AddWithValue("@Email", tb_email.Text.Trim());
                            cmd.Parameters.AddWithValue("@PasswordHash", finalHash);
                            cmd.Parameters.AddWithValue("@PasswordSalt", salt);
                            cmd.Parameters.AddWithValue("@Dateofbirth", tb_dob.Text.Trim());
                            cmd.Parameters.AddWithValue("@IV", Convert.ToBase64String(IV));
                            cmd.Parameters.AddWithValue("@Key", Convert.ToBase64String(Key));

                            cmd.Connection = con;
                            con.Open();
                            cmd.ExecuteNonQuery();
                            con.Close();
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
        }

        protected byte[] encryptData(string data)
        {
            byte[] cipherText = null;
            try
            {
                RijndaelManaged cipher = new RijndaelManaged();
                cipher.IV = IV;
                cipher.Key = Key;

                ICryptoTransform encryptTransform = cipher.CreateEncryptor();
                //ICryptoTransform decryptTransform = cipher.CreateDecryptor();
                byte[] plainText = Encoding.UTF8.GetBytes(data);
                cipherText = encryptTransform.TransformFinalBlock(plainText, 0, plainText.Length);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { }
            return cipherText;
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

