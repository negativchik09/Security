namespace Security.Auth.Models;

public class SetRoleRequest
{
    public string UserName { get; set; }
    public string NewRole { get; set; }
}