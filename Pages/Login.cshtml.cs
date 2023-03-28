using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using BlazingMudShopAuth.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BlazingMudShopAuth.Pages;

[AllowAnonymous]
[IgnoreAntiforgeryToken]
public class Login : PageModel
{
    [BindProperty] public InputModel Input { get; set; } = new();

    public string ReturnUrl { get; set; } = string.Empty;

    public class InputModel
    {
        [Required]
        [Display(Name = "Username")]
        [StringLength(32, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.",
            MinimumLength = 6)]
        public string Username { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [StringLength(32, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.",
            MinimumLength = 8)]
        public string Password { get; set; } = string.Empty;
    }

    public async Task OnGetAsync(string returnUrl = "")
    {
        // Clear the existing external cookie
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        returnUrl ??= Url.Content("~/");

        ReturnUrl = returnUrl;
    }

    
    public async Task<IActionResult> OnPostAsync(string returnUrl = "")
    {
        ReturnUrl = returnUrl;

        if (!ModelState.IsValid)
            return Page();

        var user = await AuthenticateUser(Input.Username, Input.Password);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username)
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            new AuthenticationProperties
            {
                IsPersistent = true
            });

        if (!Url.IsLocalUrl(returnUrl))
        {
            returnUrl = Url.Content("~/");
        }

        return LocalRedirect(returnUrl);

        // Something failed. Redisplay the form.
    }

    private async Task<User?> AuthenticateUser(string login, string password)
    {
        if (string.IsNullOrEmpty(login) || string.IsNullOrEmpty(password))
            return null;

        // For demonstration purposes, authenticate a user
        // with a static login name and password.
        // Assume that checking the database takes 500ms

        await Task.Delay(500);

        if (login.ToUpper() != "ADMINISTRATOR" || password != "P@ssw0rd")
            return null;

        return new User() { Username = "Administrator" };
    }
}