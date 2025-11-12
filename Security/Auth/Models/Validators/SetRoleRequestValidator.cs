using FluentValidation;

namespace Security.Auth.Models.Validators;

public class SetRoleRequestValidator : AbstractValidator<SetRoleRequest>
{
    public SetRoleRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty()
            .WithMessage("Username is required");

        RuleFor(x => x.Role)
            .NotEmpty()
            .WithMessage("Role is required");
    }
}