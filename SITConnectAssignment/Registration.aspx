<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Registration.aspx.cs" Inherits="SITConnectAssignment.Registration" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
    <style type="text/css">
        .auto-style1 {
            height: 26px;
            width: 1444px;
        }
        .auto-style4 {
            width: 63%;
            margin-right: 41px;
        }
        .auto-style6 {
            height: 30px;
            width: 1444px;
        }
        .auto-style8 {
            margin-left: 0px;
        }
        .auto-style9 {
            height: 26px;
            width: 460px;
        }
        .auto-style10 {
            width: 460px;
        }
        .auto-style11 {
            height: 30px;
            width: 460px;
        }
        .auto-style12 {
            width: 1444px;
        }
        .auto-style13 {
            width: 460px;
            height: 29px;
        }
        .auto-style14 {
            width: 1444px;
            height: 29px;
        }
        .auto-style15 {
            width: 460px;
            height: 27px;
        }
        .auto-style16 {
            width: 1444px;
            height: 27px;
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
                document.getElementById("lbl_cfmchecker").innerHTML = "Password and Confirm Password must be the same value"
                document.getElementById("lbl_cfmchecker").style.color = "Red"
                return ("Password not same")
            }

            document.getElementById("lbl_cfmchecker").innerHTML = ""

            document.getElementById("btn_submit").disabled = false;
        }
    </script>
</head>
<body>
    <form id="form1" runat="server">
        <div>
            <br />
            <asp:Label ID="Label7" runat="server" Font-Size="Larger" Text="Registration"></asp:Label>
            <br />
            <br />
            <table class="auto-style4">
                <tr>
                    <td class="auto-style9" >
                        <asp:Label ID="Label1" runat="server" Text="First Name: " Width="272px" Height="22px"></asp:Label>
                    </td>
                    <td class="auto-style1">
                        <asp:TextBox ID="tb_firstname" runat="server"></asp:TextBox>
                    </td>
                    <td class="auto-style1">
                        <asp:Label ID="lbl_firstnamechecker" runat="server" ForeColor="#CC3300"></asp:Label>
                    </td>
                </tr>
                <tr>
                    <td class="auto-style10">
                        <asp:Label ID="Label2" runat="server" Text="Last Name: "></asp:Label>
                    </td>
                    <td class="auto-style12">
                        <asp:TextBox ID="tb_lastname" runat="server"></asp:TextBox>
                    </td>
                    <td class="auto-style1">
                        <asp:Label ID="lbl_lastnamechecker" runat="server" ForeColor="#CC3300"></asp:Label>
                    </td>
                </tr>
                <tr>
                    <td class="auto-style13">
                        <asp:Label ID="Label3" runat="server" Text="Credit Card Number: "></asp:Label>
                    </td>
                    <td class="auto-style14">
                        <asp:TextBox ID="tb_creditcardNum" runat="server"></asp:TextBox>
                    </td>
                    <td class="auto-style1">
                        <asp:Label ID="lbl_numberchecker" runat="server" ForeColor="#CC3300"></asp:Label>
                    </td>
                </tr>
                <tr>
                    <td class="auto-style13">
                        Credit Card
                        <br />
                        Expiry Date (YYYY-MM-DD):</td>
                    <td class="auto-style14">
                        <asp:TextBox ID="tb_creditcardExp" runat="server"></asp:TextBox>
                    </td>
                    <td class="auto-style1">
                        <asp:Label ID="lbl_expirychecker" runat="server" ForeColor="#CC3300"></asp:Label>
                    </td>
                </tr>
                <tr>
                    <td class="auto-style13">
                        Credit Card<br />
                        CVV:</td>
                    <td class="auto-style14">
                        <asp:TextBox ID="tb_creditcardCVV" runat="server"></asp:TextBox>
                    </td>
                    <td class="auto-style1">
                        <asp:Label ID="lbl_cvvchecker" runat="server" ForeColor="#CC3300"></asp:Label>
                    </td>
                </tr>
                <tr>
                    <td class="auto-style15">
                        <asp:Label ID="Label4" runat="server" Text="Email: "></asp:Label>
                    </td>
                    <td class="auto-style16">
                        <asp:TextBox ID="tb_email" runat="server" CssClass="auto-style8"></asp:TextBox>
                    </td>
                    <td class="auto-style1">
                        <asp:Label ID="lbl_emailchecker" runat="server" ForeColor="#CC3300"></asp:Label>
                    </td>
                </tr>
                <tr>
                    <td class="auto-style11">
                        <asp:Label ID="Label5" runat="server" Text="Password: "></asp:Label>
                    </td>
                    <td class="auto-style6">
                        <asp:TextBox ID="tb_password" runat="server" TextMode="Password" onkeyup="javascript:validate()"></asp:TextBox>
                    </td>
                    <td class="auto-style1">
                        <asp:Label ID="lbl_pwdchecker" runat="server" ForeColor="#CC3300"></asp:Label>
                    </td>
                </tr>
                <tr>
                    <td class="auto-style11">
                        <asp:Label ID="Label8" runat="server" Text="Confirm Password: "></asp:Label>
                    </td>
                    <td class="auto-style6">
                        <asp:TextBox ID="tb_cfmPassword" runat="server" TextMode="Password" onkeyup="javascript:validate()"></asp:TextBox>
                    </td>
                    <td class="auto-style1">
                        <asp:Label ID="lbl_cfmchecker" runat="server" ForeColor="#CC3300"></asp:Label>
                    </td>
                </tr>
                <tr>
                    <td class="auto-style9">Password must have at least:<br />
                        •
                        8 Digits<br />
                        • 1 Uppercase &amp; 1 Lowercase letter<br />
                        •
                        1 Special Character<br />
                        •
                        1 Number<br />
                    </td>
                </tr>
                <tr>
                    <td class="auto-style10">
                        <asp:Label ID="Label6" runat="server" Text="Date of Birth (YYYY-MM-DD): "></asp:Label>
                    </td>
                    <td class="auto-style12">
                        <asp:TextBox ID="tb_dob" runat="server"></asp:TextBox>
                    </td>
                    <td class="auto-style1">
                        <asp:Label ID="lbl_dobchecker" runat="server" ForeColor="#CC3300"></asp:Label>
                    </td>
                </tr>
            </table>
        </div>
        <asp:Button ID="btn_submit" runat="server" OnClick="btn_submit_Click" Text="Submit" Enabled="False" />
        <br />
        <asp:Label ID="lbl_submitchecker" runat="server"></asp:Label>

        <input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response"/>
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
