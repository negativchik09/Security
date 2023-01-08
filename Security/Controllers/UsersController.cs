using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Security.Auth;
using Security.Auth.Models;

namespace Security.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UsersController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IConfiguration _configuration;

    public UsersController(
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        SignInManager<IdentityUser> signInManager,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    [HttpPost("register")]
    [ProducesResponseType(200)]
    [ProducesResponseType(409)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        var userExists = await _userManager.FindByNameAsync(model.Username);
        
        if (userExists != null) return Conflict();

        IdentityUser user = new()
        {
            Email = model.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = model.Username
        };
        
        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
        {
            return StatusCode(StatusCodes.Status500InternalServerError);
        }

        await _userManager.AddToRoleAsync(user, UserRoles.Worker);
        return Ok();
    }

    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(403)]
    [ProducesResponseType(404)]
    [ProducesResponseType(500)]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _userManager.FindByNameAsync(model.Username);
        
        if (user == null) return NotFound();

        var result = await _signInManager.PasswordSignInAsync(
            user: user, 
            password: model.Password, 
            isPersistent: false, 
            lockoutOnFailure: false);

        if (result.IsLockedOut) return Forbid();

        if (!result.Succeeded) return BadRequest();

        var userRoles = await _userManager.GetRolesAsync(user);

        var authClaims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName),
            new(MyClaims.Id, user.Id),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        
        authClaims.AddRange(userRoles.Select(userRole => new Claim(ClaimTypes.Role, userRole)));

        var token = GetToken(authClaims);
        
        return Ok(new LoginResponse()
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            Role = userRoles.Single()
        });
    }

    [Authorize(Roles = UserRoles.Admin)]
    [ProducesResponseType(typeof(IEnumerable<UsersResponse>), 200)]
    [HttpGet("get-users")]
    public async Task<IActionResult> GetUsers()
    {
        var result = _userManager.Users.AsNoTracking().AsEnumerable();
        return Ok(result.Select(async x => new UsersResponse()
        {
            UserName = x.UserName,
            Role = (await _userManager.GetRolesAsync(x)).Single()
        }));
    }
    
    [Authorize(Roles = UserRoles.Admin)]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    [HttpPut("set-user-role")]
    public async Task<IActionResult> SetUserRole([FromBody] SetRoleRequest request)
    {
        if (!UserRoles.List.Contains(request.NewRole)) return BadRequest();
        
        var user = await _userManager.FindByNameAsync(request.UserName);
        if (user == null) return NotFound();

        var roles = await _userManager.GetRolesAsync(user);

        if (roles.Contains(request.NewRole)) return Ok();

        await _userManager.RemoveFromRolesAsync(user, roles);
        await _userManager.AddToRoleAsync(user, request.NewRole);

        return Ok();
    }
    
    [Authorize(Roles = UserRoles.Admin)]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [HttpPut("block-user")]
    public async Task<IActionResult> BlockUser([FromBody] BlockingUserRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.UserName);
        if (user == null) return BadRequest();

        user.LockoutEnd = DateTimeOffset.Now + TimeSpan.FromDays(365 * 100);
        await _userManager.UpdateAsync(user);

        return Ok();
    }
    
    [Authorize(Roles = UserRoles.Admin)]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [HttpPut("unblock-user")]
    public async Task<IActionResult> UnblockUser([FromBody] BlockingUserRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.UserName);
        if (user == null) return BadRequest();

        user.LockoutEnd = DateTimeOffset.Now + TimeSpan.FromSeconds(5);
        await _userManager.UpdateAsync(user);

        return Ok();
    }
    
    [Authorize]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [HttpPut("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var name = User.Claims.First(x => x.Type == ClaimTypes.Name).Value;
        var user = await _userManager.FindByNameAsync(name);
        if (user == null) return BadRequest();

        var result = await _userManager.ChangePasswordAsync(user, request.OldPassword, request.NewPassword);

        if (!result.Succeeded)
        {
            return BadRequest();
        }

        return Ok();
    }

    private JwtSecurityToken GetToken(List<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            expires: DateTime.Now.AddHours(1),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );

        return token;
    }
}