namespace Security.Auth;

public static class UserRoles
{
    public const string Admin = "Admin";
    public const string Manager = "Manager";
    public const string Worker = "Worker";
    public static string[] List => new[] { Admin, Manager, Worker };
}