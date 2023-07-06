using DShopAPI.ViewModels.Dtos;

namespace DShopAPII.ViewModels.User
{
    public class UserViewModel
    {
        public UserLoginDto LoginDto { get; set; }
        public UserRegistrationDto RegistrationDto { get; set; }
        public ResetPasswordConfirmDto ResetPasswordDto { get; set; }
    }

}
