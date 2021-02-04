<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="ChangePassword.aspx.cs" Inherits="SITConnectAssignment.ChangePassword" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
    <style type="text/css">

        .auto-style1 {
            width: 36%;
        }
    </style>

    <script src="https://www.google.com/recaptcha/api.js?render=6LfNt-sZAAAAAFNy9lUXnfG4dp-Hl_Z09yDJnBZO"></script>


    <%-- Client Side Password Complexity Checker --%>
    <script type="text/javascript">
        //Password onchange validation
        function validate() {
            var password = document.getElementById("tb_password").value;
            var cfmPassword = document.getElementById("tb_cfmPassword").value;

            var feedback = document.getElementById("lbl_pwdchecker")

            document.getElementById("btn_submit").disabled = true;

            if (password.length < 8) {
                feedback.innerHTML = "Password length must be at least 8 characters."
                feedback.style.color = "Red"
                return ("too_short")
            } else if (password.search(/^(?=.*[A-Z])/) == -1) {
                feedback.innerHTML = "Password requires at least 1 uppercase";
                feedback.style.color = "Red"
                return ("no_uppercase")
            } else if (password.search(/^(?=.*[a-z])/) == -1) {
                feedback.innerHTML = "Password requires at least 1 lowercase";
                feedback.style.color = "Red"
                return ("no_lowercase")
            } else if (password.search(/^(?=.*[$@$!%*?&])/) == -1) {
                feedback.innerHTML = "Password requires at least 1 special character";
                feedback.style.color = "Red"
                return ("no_number")
            } else if (password.search(/^(?=.*\d)/) == -1) {
                feedback.innerHTML = "Password requires at least 1 number";
                feedback.style.color = "Red"
                return ("no_special_character")
            } else {
                feedback.innerHTML = "Excellent!"
                feedback.style.color = "Blue"
            }

            if (password != cfmPassword) {
                feedback.innerHTML = "Password and Confirm Password must be the same value"
                feedback.style.color = "Red"
                return ("Password not same")
            }


            document.getElementById("btn_submit").disabled = false;
        }
    </script>
</head>
<body>
    <form id="form2" runat="server">
        <div>
            <asp:Label ID="Label7" runat="server" Font-Size="Larger" Text="Change Password"></asp:Label>
            <br />
            <asp:Label ID="Label1" runat="server" Text="Please note that you will be logged out once this is successful."></asp:Label>
            <br />
            <br />
            <table class="auto-style1">
                <tr>
                    <td>New Password:</td>
                    <td>
                        <asp:TextBox ID="tb_password" runat="server" TextMode="Password" onkeyup="javascript:validate()"></asp:TextBox>
                    </td>
                </tr>
                <tr>
                    <td>Confirm New Password: </td>
                    <td>
                        <asp:TextBox ID="tb_cfmPassword" TextMode="Password" runat="server" onkeyup="javascript:validate()"></asp:TextBox>
                    </td>
                </tr>
            </table>
            <br />
            <asp:Label ID="lbl_pwdchecker" runat="server"></asp:Label>
            <br />
            <asp:Button ID="btn_submit" runat="server" OnClick="btn_submit_Click" Text="Submit" />

            <input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response"/>

        </div>


    </form>


    <script>
        grecaptcha.ready(function () {
            grecaptcha.execute('6LfNt-sZAAAAAFNy9lUXnfG4dp-Hl_Z09yDJnBZO', { action: 'Login' }).then(function (token) {
                document.getElementById("g-recaptcha-response").value = token;
            });
        });
    </script>

</body>
</html>
