using FluentValidation;

namespace Security.Auth.Models.Validators;

public class ChangePasswordRequestValidator : AbstractValidator<ChangePasswordRequest>
{
    public ChangePasswordRequestValidator()
    {
        RuleFor(x => x.OldPassword)
            .NotEmpty()
            .WithMessage("OldPassword is required");

        RuleFor(x => x.NewPassword)
            .NotEmpty()
            .WithMessage("NewPassword is required");
    }
}