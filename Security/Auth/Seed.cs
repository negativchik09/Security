using Microsoft.AspNetCore.Identity;

namespace Security.Auth;

public static class Seed
{
    public static async void Initialize(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        
        using var roleManager = scope.ServiceProvider.GetService<RoleManager<IdentityRole>>();
        using var userManager = scope.ServiceProvider.GetService<UserManager<IdentityUser>>();

        if (roleManager == null || userManager == null)
        {
            return;
        }

        string[] roles = { UserRoles.Manager, UserRoles.Worker, UserRoles.Admin };
        
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
            await userManager.AddToRoleAsync(admin, UserRoles.Admin);
        }
        
        if (await userManager.FindByNameAsync("manager") == null)
        {
            var manager = new IdentityUser()
            {
                UserName = "manager"
            };
            await userManager.CreateAsync(manager, "Manager_password1");
            await userManager.AddToRoleAsync(manager, UserRoles.Manager);
        }
        
        if (await userManager.FindByNameAsync("worker") == null)
        {
            var worker = new IdentityUser()
            {
                UserName = "worker"
            };
            await userManager.CreateAsync(worker, "Worker_password1");
            await userManager.AddToRoleAsync(worker, UserRoles.Worker);
        }
    }
}