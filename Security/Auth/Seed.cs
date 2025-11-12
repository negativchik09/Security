using Microsoft.AspNetCore.Identity;

namespace Security.Auth;

public static class Seed
{
    public const string AdminRole = "Admin";
    public static async void Initialize(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        
        using var roleManager = scope.ServiceProvider.GetService<RoleManager<IdentityRole>>();
        using var userManager = scope.ServiceProvider.GetService<UserManager<IdentityUser>>();

        if (roleManager == null || userManager == null)
        {
            return;
        }

        string[] roles = ["Admin"];
        
        foreach (string role in roles)
        {
            if (!roleManager.Roles.Any(r => r.Name == role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
        }

        if (await userManager.FindByNameAsync("admin") == null)
        {
            var admin = new IdentityUser()
            {
                UserName = "admin"
            };
            await userManager.CreateAsync(admin, "Admin_password1");
            await userManager.AddToRoleAsync(admin, AdminRole);
        }
    }
}