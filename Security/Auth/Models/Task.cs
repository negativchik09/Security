namespace Security.Auth.Models;

public class Task
{
    public int Id { get; set; }
    public string Title { get; set; }
    public string Description { get; set; }
    public DateTime AssignDateTime { get; set; }
    public DateTime? FinishDateTime { get; set; }
    public string UserId { get; set; }
    public string ManagerId { get; set; }
}