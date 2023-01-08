using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Security.Auth;
using Security.Auth.Models;
using Task = Security.Auth.Models.Task;

namespace Security.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TaskController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public TaskController(ApplicationDbContext context)
    {
        _context = context;
    }

    [Authorize]
    [HttpGet("")]
    [ProducesResponseType(typeof(List<Task>), 200)]
    [ProducesResponseType(typeof(object), 401)]
    public async Task<IActionResult> GetAll()
    {
        var role = User.Claims.Single(x => x.Type == ClaimTypes.Role).Value;
        var id = User.Claims.First(x => x.Type == MyClaims.Id).Value;
        return role switch
        {
            UserRoles.Manager => await GetByManagerId(id),
            UserRoles.Worker => await GetByWorkerId(id),
            UserRoles.Admin => Ok(await _context.Tasks.ToListAsync()),
            _ => BadRequest()
        };
    }
    
    private async Task<IActionResult> GetByWorkerId(string userId)
    {
        List<Task> result = await _context.Tasks.AsNoTracking().Where(x => x.UserId == userId).ToListAsync();
        return Ok(result);
    }
    
    private async Task<IActionResult> GetByManagerId(string managerId)
    {
        List<Task> result = await _context.Tasks.AsNoTracking().Where(x => x.ManagerId == managerId).ToListAsync();
        return Ok(result);
    }
    
    [Authorize]
    [HttpGet("{taskId:int}")]
    [ProducesResponseType(typeof(Task), 200)]
    [ProducesResponseType(403)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> GetByTaskId(int taskId)
    {
        var task = await _context.Tasks.FirstOrDefaultAsync(x => x.Id == taskId);
        if (task == null)
        {
            return NotFound();
        }

        var id = User.Claims.First(x => x.Type == MyClaims.Id).Value;
        if (id != task.UserId && id != task.ManagerId)
        {
            return Forbid();
        }
        
        return Ok(task);
    }
    
    [Authorize(Roles = UserRoles.Worker)]
    [HttpGet("complete/{taskId:int}")]
    [ProducesResponseType(typeof(Task), 200)]
    [ProducesResponseType(403)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> CompleteTaskById(int taskId)
    {
        var task = _context.Tasks.FirstOrDefault(x => x.Id == taskId);
        if (task == null)
        {
            return NotFound();
        }
        
        var id = User.Claims.First(x => x.Type == MyClaims.Id).Value;
        if (id != task.UserId)
        {
            return Forbid();
        }

        if (task.FinishDateTime == null)
        {
            task.FinishDateTime = DateTime.Now;
        }
        else
        {
            task.FinishDateTime = null;
        }

        _context.Tasks.Update(task);
        
        await _context.SaveChangesAsync();
        
        return Ok(task);
    }

    [Authorize]
    [HttpPost("")]
    [ProducesResponseType(typeof(Task), 200)]
    public async Task<IActionResult> CreateTask([FromBody] CreatingTask task)
    {
        var managerId = User.Claims.First(x => x.Type == MyClaims.Id).Value;
        var newTask = new Task()
        {
            AssignDateTime = DateTime.Now,
            FinishDateTime = null,
            Title = task.Title,
            Description = task.Description,
            ManagerId = managerId,
            UserId = managerId
        };
        await _context.Tasks.AddAsync(newTask);
        await _context.SaveChangesAsync();

        return Ok(newTask);
    }
    
    [Authorize(Roles = UserRoles.Manager)]
    [HttpDelete("{taskId:int}")]
    [ProducesResponseType(typeof(Task), 200)]
    [ProducesResponseType(403)]
    public async Task<IActionResult> DeleteByTaskId(int taskId)
    {
        var result = _context.Tasks.AsNoTracking().FirstOrDefault(x => x.Id == taskId);
        if (result == null)
        {
            return Ok();
        }

        var managerId = User.Claims.First(x => x.Type == MyClaims.Id).Value;
        if (managerId != result.ManagerId)
        {
            return Forbid();
        }
        
        _context.Tasks.Remove(result);
        await _context.SaveChangesAsync();
        return Ok();
    }
}