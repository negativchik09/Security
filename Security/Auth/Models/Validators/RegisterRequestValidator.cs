using FluentValidation;

namespace Security.Auth.Models.Validators;

public class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty()
            .WithMessage("Username is required");

        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage("Password is required");

        RuleFor(x => x.Role)
            .NotEmpty()
            .WithMessage("Username is required");
    }
}