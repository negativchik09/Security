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
    [Authorize(Roles = Seed.AdminRole)]
    [ProducesResponseType(200)]
    [ProducesResponseType(typeof(string), 409)]
    [ProducesResponseType(typeof(string), 500)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username);
        
        if (user != null) return Conflict("User with this username already exists.");
        
        var role = await _roleManager.FindByNameAsync(request.Role);

        if (role == null)
        {
            var createRoleResult = await _roleManager.CreateAsync(new IdentityRole(request.Role));
            if (!createRoleResult.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, 
                    string.Join(Environment.NewLine, 
                        createRoleResult.Errors.Select(x => x.Description)));
            }
            role = await _roleManager.FindByNameAsync(request.Role);
        }

        user = new()
        {
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = request.Username
        };
        
        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, 
                string.Join(Environment.NewLine, 
                    result.Errors.Select(x => x.Description)));
        }

        await _userManager.AddToRoleAsync(user, role!.Name!);;
        return Ok();
    }

    [ProducesResponseType(typeof(LoginResponse), 200)]
    [ProducesResponseType(typeof(string), 400)]
    [ProducesResponseType(typeof(string), 404)]
    [ProducesResponseType(typeof(string), 500)]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username);
        
        if (user == null) return NotFound("User with this username not exists");

        var result = await _signInManager.PasswordSignInAsync(
            user: user, 
            password: request.Password, 
            isPersistent: false, 
            lockoutOnFailure: false);

        if (!result.Succeeded) return BadRequest("Invalid login attempt");

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

    [HttpGet]
    [Authorize(Roles = Seed.AdminRole)]
    [ProducesResponseType(typeof(IEnumerable<UsersResponse>), 200)]
    public async Task<IActionResult> GetUsers()
    {
        var result = _userManager.Users.AsNoTracking().AsEnumerable();
        return Ok(result.Select(async x => new UsersResponse()
        {
            UserName = x.UserName,
            Role = (await _userManager.GetRolesAsync(x)).Single()
        }));
    }
    
    [Authorize(Roles = Seed.AdminRole)]
    [ProducesResponseType(200)]
    [ProducesResponseType(typeof(string), 400)]
    [ProducesResponseType(typeof(string), 404)]
    [HttpPut("role/set")]
    public async Task<IActionResult> SetUserRole([FromBody] SetRoleRequest request)
    {
        var role = await _roleManager.FindByNameAsync(request.Role);

        if (role == null) return BadRequest();
        
        var user = await _userManager.FindByNameAsync(request.Username);
        if (user == null) return NotFound();

        var roles = await _userManager.GetRolesAsync(user);

        if (roles.Contains(request.Role)) return Ok();

        await _userManager.RemoveFromRolesAsync(user, roles);
        await _userManager.AddToRoleAsync(user, request.Role);

        return Ok();
    }
    
    [Authorize]
    [HttpPut("password/change")]
    [ProducesResponseType(200)]
    [ProducesResponseType(typeof(string), 400)]
    [ProducesResponseType(typeof(string), 403)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var name = User.Claims.First(x => x.Type == ClaimTypes.Name).Value;
        var user = await _userManager.FindByNameAsync(name);
        if (user == null) return Forbid("Username from token not found. Reauthenticate and try again.");

        var result = await _userManager.ChangePasswordAsync(user, request.OldPassword, request.NewPassword);

        if (!result.Succeeded)
        {
            return BadRequest(string.Join(Environment.NewLine, result.Errors.Select(x => x.Description)));;
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