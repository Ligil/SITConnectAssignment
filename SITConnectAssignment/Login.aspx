<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Login.aspx.cs" Inherits="SITConnectAssignment.Login" %>

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


</head>
<body>
    <form id="form1" runat="server">
        <div>
            <br />
            <asp:Label ID="Label7" runat="server" Font-Size="Larger" Text="Login"></asp:Label>
            <br />
            <br />
            <table class="auto-style1">
                <tr>
                    <td>Email:</td>
                    <td>
                        <asp:TextBox ID="tb_email" runat="server"></asp:TextBox>
                    </td>
                </tr>
                <tr>
                    <td>Password: </td>
                    <td>
                        <asp:TextBox ID="tb_password" TextMode="Password" runat="server" OnTextChanged="tb_password_TextChanged"></asp:TextBox>
                    </td>
                </tr>
            </table>
            <asp:Button ID="btn_submit" runat="server" OnClick="btn_submit_Click" Text="Submit" />
            <br />
            <asp:Label ID="lbl_errormsg" runat="server"></asp:Label>

            <input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response"/>

        </div>
    </form>

    <asp:HyperLink ID="HyperLink1" runat="server" NavigateUrl="~/Registration.aspx">Click here to Register</asp:HyperLink>
    <br />
    <asp:Label ID="lbl_gScore" runat="server" ></asp:Label>


    <script>
        grecaptcha.ready(function () {
            grecaptcha.execute('6LfNt-sZAAAAAFNy9lUXnfG4dp-Hl_Z09yDJnBZO', { action: 'Login' }).then(function (token) {
                document.getElementById("g-recaptcha-response").value = token;
            });
        });
    </script>

</body>
</html>
