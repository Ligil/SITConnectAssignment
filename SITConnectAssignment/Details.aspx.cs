using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

using System.Data;
using System.Data.SqlClient;
using System.Configuration;



namespace SITConnectAssignment
{

    public partial class Details : System.Web.UI.Page
    {
        string MYDBConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["SITConnectDB"].ConnectionString;

        protected void Page_Load(object sender, EventArgs e)
        {
            if (Session["UserID"] != null && Session["AuthToken"] != null && Request.Cookies["AuthToken"] != null){
                if (!Session["AuthToken"].ToString().Equals(Request.Cookies["AuthToken"].Value))
                {
                    Response.Redirect("Login.aspx", false);
                }
                else if(DateTime.Now > getDateTime().AddMinutes(15))
                {
                    Response.Redirect("ChangePassword.aspx", false);
                } 
                else 
                {
                    //Insert Details page codes here
                    DataSet dset = new DataSet();
                    DataSet profileDset = new DataSet();
                    SqlConnection conn = new SqlConnection(ConfigurationManager.ConnectionStrings["SITConnectDB"].ToString());
                    using (conn)
                    {
                        conn.Open();
                        SqlDataAdapter adapter = new SqlDataAdapter();

                        SqlCommand cmd = new SqlCommand("SELECT Id, Firstname, Lastname, CCnumber, CCexpdate, CCcvv, Email, PasswordHash, PasswordSalt, Dateofbirth FROM Account", conn);
                        cmd.CommandType = CommandType.Text;
                        adapter.SelectCommand = cmd;
                        adapter.Fill(dset);

                        cmd = new SqlCommand("SELECT Id, Firstname, Lastname, CCnumber, CCexpdate, CCcvv, Email, PasswordHash, PasswordSalt, Dateofbirth FROM Account WHERE lower(Email) = @Email", conn);
                        cmd.Parameters.AddWithValue("@Email", Session["UserID"].ToString().ToLower());
                        cmd.CommandType = CommandType.Text;
                        adapter.SelectCommand = cmd;
                        adapter.Fill(profileDset);

                        lbl_fullname.Text = HttpUtility.HtmlEncode(profileDset.Tables[0].Rows[0]["Firstname"].ToString()) + " " + HttpUtility.HtmlEncode(profileDset.Tables[0].Rows[0]["Lastname"].ToString());
                        lbl_ccNum.Text = HttpUtility.HtmlEncode(profileDset.Tables[0].Rows[0]["CCnumber"].ToString());
                        lbl_expiry.Text = HttpUtility.HtmlEncode(profileDset.Tables[0].Rows[0]["CCexpdate"].ToString());
                        lbl_cvv.Text = HttpUtility.HtmlEncode(profileDset.Tables[0].Rows[0]["CCcvv"].ToString());
                        lbl_email.Text = HttpUtility.HtmlEncode(profileDset.Tables[0].Rows[0]["Email"].ToString());
                        lbl_passwordHash.Text = HttpUtility.HtmlEncode(profileDset.Tables[0].Rows[0]["PasswordHash"].ToString());
                        lbl_dob.Text = HttpUtility.HtmlEncode(profileDset.Tables[0].Rows[0]["Dateofbirth"].ToString());

                        gvUserInfo.DataSource = dset;
                        gvUserInfo.DataBind();
                    }


                }
            }
            else
            {
                Response.Redirect("Login.aspx", false);
            }

        }

        protected void btn_logout_Click(object sender, EventArgs e)
        {
            Session.Remove("UserID");
            Response.Redirect("Login.aspx", false);

            if (Request.Cookies["ASP.NET_SessionId"] != null)
            {
                Response.Cookies["ASP.NET_SessionId"].Value = string.Empty;
                Response.Cookies["ASP.NET_SessionId"].Expires = DateTime.Now.AddMonths(-20);
            }
            if (Request.Cookies["AuthToken"] != null)
            {
                Response.Cookies["AuthToken"].Value = string.Empty;
                Response.Cookies["AuthToken"].Expires = DateTime.Now.AddMonths(-20);
            }

        }

        protected void ChangePasswordBtn_Click(object sender, EventArgs e)
        {
            if (Session["UserID"] != null && Session["AuthToken"] != null && Request.Cookies["AuthToken"] != null)
            {
                if (!Session["AuthToken"].ToString().Equals(Request.Cookies["AuthToken"].Value))
                {
                    Response.Redirect("Login.aspx", false);
                }
                else
                {
                    DateTime time = getDateTime();
                    if (DateTime.Now > time.AddMinutes(3))
                    {
                        Response.Redirect("ChangePassword.aspx", false);
                    }
                    else
                    {
                        //Recently changed password, nothing happens
                        ScriptManager.RegisterClientScriptBlock(this, this.GetType(), "alertMessage", "alert('Password Recently Changed, please wait till " + time.AddMinutes(5).ToString() + "')", true);
                    }
                }
            }


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
    }
}