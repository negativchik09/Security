﻿namespace Security.Auth.Models;

public class LoginResponse
{
    public string Token { get; set; }
    public string Role { get; set; }
}