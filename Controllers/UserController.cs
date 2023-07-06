using System;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using DShopAPI.Data;
using DShopAPI.Models;
using DShopAPI.ViewModels;
using DShopAPI.ViewModels.Dtos;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using BCrypt.Net;
using Microsoft.EntityFrameworkCore;
using System.Web;
using DShopAPII.ViewModels.User;

namespace DShopAPII.Controllers
{
    [Route("User/[controller]")]
    public class UserController : Controller
    {
        private readonly DShopDbContext _dbContext;
        private readonly SmtpSettings _smtpSettings;

        public UserController(DShopDbContext dbContext, IOptions<SmtpSettings> smtpSettings)
        {
            _dbContext = dbContext;
            _smtpSettings = smtpSettings.Value;
        }

        public IActionResult Login()
        {
            var model = new UserLoginDto();
            return View(model);
        }

        [HttpPost("Login")]
        public IActionResult Login(UserLoginDto userDto)
        {
            var user = _dbContext.Users.SingleOrDefault(u => u.Email == userDto.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "User does not exist.");
                return View(userDto);
            }

            if (!BCrypt.Net.BCrypt.Verify(userDto.Password, user.Password))
            {
                ModelState.AddModelError("", "Incorrect password.");
                return View(userDto);
            }

            return RedirectToAction("Index", "Home");
        }

        public IActionResult Registration()
        {
            var model = new UserRegistrationDto();
            return View(model);
        }

        [HttpPost("Registration")]
        public async Task<IActionResult> Registration(UserRegistrationDto userDto)
        {
            try
            {
                if (_dbContext.Users.Any(u => u.Email == userDto.Email || u.UserName == userDto.UserName))
                {
                    ModelState.AddModelError("", "Email or username already exists.");
                    return View(userDto);
                }

                string otp = GenerateOTP();

                var user = new Users
                {
                    Email = userDto.Email,
                    Password = BCrypt.Net.BCrypt.HashPassword(userDto.Password),
                    PhoneNumber = userDto.PhoneNumber,
                    UserName = userDto.UserName,
                    ConfirmationCode = otp,
                    VerificationCodeExpiration = DateTime.UtcNow.AddMinutes(10)
                };

                _dbContext.Users.Add(user);
                await _dbContext.SaveChangesAsync();

                bool otpSent = SendOTP(userDto.Email, otp);

                if (!otpSent)
                {
                    ModelState.AddModelError("", "Failed to send OTP. Please try again later.");
                    return View(userDto);
                }

                return RedirectToAction("Verify");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", ex.Message);
                return View(userDto);
            }
        }

        public IActionResult Verify()
        {
            var model = new VerificationDto();
            return View(model);
        }

        [HttpPost("Verify")]
        public async Task<IActionResult> Verify(VerificationDto verificationDto)
        {
            var user = _dbContext.Users.SingleOrDefault(u => u.ConfirmationCode == verificationDto.Code);

            if (user == null)
            {
                ModelState.AddModelError("", "Incorrect verification code.");
                return View(verificationDto);
            }

            if (user.VerificationCodeExpiration < DateTime.UtcNow)
            {
                ModelState.AddModelError("", "Verification code has expired. Please request a new one.");
                return View(verificationDto);
            }

            user.ConfirmationCode = null;
            await _dbContext.SaveChangesAsync();

            string emailBody = "Your verification is successful. You can now proceed with your login.";

            bool emailSent = SendEmail(user.Email, "Verification Successful", emailBody);

            if (!emailSent)
            {
                ModelState.AddModelError("", "Failed to send email notification. Please try again later.");
                return View(verificationDto);
            }

            return RedirectToAction("Login");
        }

        public IActionResult ResetPassword()
        {
            var model = new ResetPasswordConfirmDto();
            return View(model);
        }

        [HttpPost("ResetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            try
            {
                var user = await _dbContext.Users.SingleOrDefaultAsync(u => u.ResetPasswordToken == resetPasswordDto.ResetToken);

                if (user == null)
                {
                    ModelState.AddModelError("", "Invalid reset token.");
                    return View(resetPasswordDto);
                }

                if (user.ResetPasswordTokenExpiration < DateTime.UtcNow)
                {
                    ModelState.AddModelError("", "Reset token has expired. Please request a new one.");
                    return View(resetPasswordDto);
                }

                if (!BCrypt.Net.BCrypt.Verify(resetPasswordDto.OldPassword, user.Password))
                {
                    ModelState.AddModelError("", "Incorrect old password.");
                    return View(resetPasswordDto);
                }

                if (resetPasswordDto.NewPassword != resetPasswordDto.ConfirmPassword)
                {
                    ModelState.AddModelError("", "New password and confirm password do not match.");
                    return View(resetPasswordDto);
                }

                user.Password = BCrypt.Net.BCrypt.HashPassword(resetPasswordDto.NewPassword);
                user.ResetPasswordToken = null;
                user.ResetPasswordTokenExpiration = null;
                await _dbContext.SaveChangesAsync();

                string emailBody = "Your password has been successfully changed.";
                bool emailSent = SendEmail(user.Email, "Password Reset Successful", emailBody);

                if (!emailSent)
                {
                    ModelState.AddModelError("", "Failed to send email. Please try again later.");
                    return View(resetPasswordDto);
                }

                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", ex.Message);
                return View(resetPasswordDto);
            }
        }

        private bool SendEmail(string email, string subject, string body)
        {
            try
            {
                MailMessage mail = new MailMessage();
                SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
                smtpClient.EnableSsl = true;

                mail.From = new MailAddress(_smtpSettings.Username);
                mail.To.Add(email);
                mail.Subject = subject;
                mail.Body = body;

                smtpClient.Send(mail);

                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        [HttpPost("reset/initiate")]
        public IActionResult InitiatePasswordReset(ResetPasswordInitiateDto initiateDto)
        {
            var user = _dbContext.Users.SingleOrDefault(u => u.Email == initiateDto.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "User not found.");
                return View(initiateDto);
            }

            string resetToken = GenerateResetToken();

            user.ResetPasswordToken = resetToken;
            user.ResetPasswordTokenExpiration = DateTime.UtcNow.AddMinutes(10);

            _dbContext.SaveChanges();

            string resetLink = $"https://bulwark.netlify.app/reset-password?token={HttpUtility.UrlEncode(resetToken)}";

            // Send the resetLink to the user's email using your email sending functionality

            return RedirectToAction("Login");
        }

        [HttpPost("resendotp")]
        public IActionResult ResendOTP(string email)
        {
            var user = _dbContext.Users.SingleOrDefault(u => u.Email == email);

            if (user == null)
            {
                ModelState.AddModelError("", "User not found.");
                return View("ResetPassword"); // Assuming you have a corresponding view for the ResetPassword action
            }

            string otp = GenerateOTP();

            user.ConfirmationCode = otp;
            _dbContext.SaveChanges();

            bool otpSent = SendOTP(user.Email, otp);

            if (!otpSent)
            {
                ModelState.AddModelError("", "Failed to send OTP. Please try again later.");
                return View("ResetPassword"); // Assuming you have a corresponding view for the ResetPassword action
            }

            return RedirectToAction("ResetPassword");
        }

        [HttpDelete("{id}")]
        public IActionResult DeleteUser(int id)
        {
            var user = _dbContext.Users.Find(id);

            if (user == null)
            {
                return NotFound("User not found.");
            }

            _dbContext.Users.Remove(user);
            _dbContext.SaveChanges();

            return Ok("User deleted successfully.");
        }

        private bool SendPasswordResetEmail(string email, string resetToken)
        {
            try
            {
                MailMessage mail = new MailMessage();
                SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
                smtpClient.EnableSsl = true;

                mail.From = new MailAddress(_smtpSettings.Username);
                mail.To.Add(email);
                mail.Subject = "Password Reset";
                mail.Body = $"Please click the following link to reset your password: {resetToken}";

                smtpClient.Send(mail);

                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }




        private bool SendOTP(string email, string otp)
        {
            try
            {
                MailMessage mail = new MailMessage();
                SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
                smtpClient.EnableSsl = true;

                mail.From = new MailAddress(_smtpSettings.Username);
                mail.To.Add(email);
                mail.Subject = "OTP Verification";
                mail.Body = $"Your OTP is: {otp}";

                smtpClient.Send(mail);

                // Set the verification code expiration time to 10 minutes from now
                TimeSpan codeExpirationTime = TimeSpan.FromMinutes(10);
                var user = _dbContext.Users.SingleOrDefault(u => u.Email == email);
                if (user != null)
                {
                    user.ConfirmationCode = otp;
                    user.VerificationCodeExpiration = DateTime.UtcNow.Add(codeExpirationTime);
                    _dbContext.SaveChanges();
                }

                return true;
            }
            catch (Exception ex)
            {
                // Handle the exception
                return false;
            }
        }

        private string GenerateOTP()
        {
            // Generate a random OTP (One-Time Password)
            // You can use any logic to generate the OTP (e.g., random number, alphanumeric code)
            Random random = new Random();
            int otpValue = random.Next(100000, 999999);
            return otpValue.ToString();
        }
        private string GenerateResetToken()
        {
            // Generate a random string for the reset token
            const int tokenLength = 64;
            const string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            Random random = new Random();
            string resetToken = new string(Enumerable.Repeat(allowedChars, tokenLength)
                .Select(s => s[random.Next(s.Length)]).ToArray());
            return resetToken;
        }

    }
}
