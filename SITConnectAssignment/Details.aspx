<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Details.aspx.cs" Inherits="SITConnectAssignment.Details" ValidateRequest="false"%>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>

    <form id="form1" runat="server">
        <asp:Label ID="Label1" runat="server" Font-Size="Larger" Text="Profile"></asp:Label>
        <br />
        <asp:Label ID="label2" runat="server" Text="Name: "></asp:Label>
        <asp:Label ID="lbl_fullname" runat="server"></asp:Label>
        <br />
        <asp:Label ID="label3" runat="server" Text="CC Number: "></asp:Label>
        <asp:Label ID="lbl_ccNum" runat="server"></asp:Label>
        <br />
        <asp:Label ID="label5" runat="server" Text="CC Expiry Date: "></asp:Label>
        <asp:Label ID="lbl_expiry" runat="server"></asp:Label>
        <br />
        <asp:Label ID="label7" runat="server" Text="CC cvv: "></asp:Label>
        <asp:Label ID="lbl_cvv" runat="server"></asp:Label>
        <br />
        <asp:Label ID="label9" runat="server" Text="Email: "></asp:Label>
        <asp:Label ID="lbl_email" runat="server"></asp:Label>
        <br />
        <asp:Label ID="label11" runat="server" Text="Password Hash: "></asp:Label>
        <asp:Label ID="lbl_passwordHash" runat="server"></asp:Label>
        <br />
        <asp:Label ID="label13" runat="server" Text="Date of Birth: "></asp:Label>
        <asp:Label ID="lbl_dob" runat="server"></asp:Label>

        <br />
        <br />

        <asp:Label ID="Label4" runat="server" Text="All Accounts"></asp:Label>
        <asp:gridview id="gvUserInfo" width="100%" runat="server" datakeynames="Id" autogeneratecolumns="False">
            <Columns>
                <asp:BoundField DataField="Id" HeaderText="Id" />
                <asp:BoundField DataField="Firstname" HeaderText="First Name" />
                <asp:BoundField DataField="Lastname" HeaderText="Last Name" />
                <asp:BoundField DataField="CCnumber" HeaderText="CC Number" />
                <asp:BoundField DataField="CCexpdate" HeaderText="CC Expiry Date" DataFormatString="{0:d}"  />
                <asp:BoundField DataField="CCcvv" HeaderText="CC cvv" />
                <asp:BoundField DataField="Email" HeaderText="Email" />
                <asp:BoundField DataField="PasswordHash" HeaderText="Password Hash" />
                <asp:BoundField DataField="PasswordSalt" HeaderText="Password Salt" />
                <asp:BoundField DataField="Dateofbirth" HeaderText="Date of Birth" DataFormatString="{0:d}" />
            </Columns>
        </asp:gridview>

        <br />

        <div>
            <asp:Button ID="btn_logout" runat="server" Text="Logout" OnClick="btn_logout_Click" />
        </div>
    </form>
</body>
</html>
