using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Login_Registration.Models;
using Microsoft.AspNetCore.Identity;

namespace Login_Registration.Controllers;

public class UserController : Controller
{
    private readonly ILogger<UserController> _logger;

    private MyContext _context;
    public UserController(ILogger<UserController> logger, MyContext context)
    {
        _logger = logger;
        _context = context;
    }

    public IActionResult Index()
    {
        return View();
    }

    // Log user out
    [HttpPost]
    [Route("Logout")]
    public ViewResult Logout()
    {
        HttpContext.Session.Clear();
        return View("Index");
    }

    // Register user
    [HttpPost("users/register")]
    public IActionResult RegisterUser(User newUser)
    {
        if (!ModelState.IsValid)
        {
            return View("Index");
        }
        // Hashing Time! 
        PasswordHasher<User> hasher = new PasswordHasher<User>();

        newUser.Password = hasher.HashPassword(newUser, newUser.Password);

        _context.Add(newUser);
        _context.SaveChanges();

        HttpContext.Session.SetInt32("UserId", newUser.UserId);
        return View("Success");
}

// Login user
[HttpPost("Success")]
public IActionResult LoginUser(LogUser logAttempt)
{
    if (!ModelState.IsValid)
    {
        return View("Index");
    }
    User? dbUser = _context.Users.FirstOrDefault(u => u.Email == logAttempt.LogEmail);
    if(dbUser == null)
    {
        ModelState.AddModelError("LogPassword", "Email/Password Not Found");
        return View("Index");
    }
    PasswordHasher<LogUser> hasher = new PasswordHasher<LogUser>();
        PasswordVerificationResult pwCompare = hasher.VerifyHashedPassword(logAttempt, dbUser.Password, logAttempt.LogPassword);
        if (pwCompare == 0)
        {
            ModelState.AddModelError("LogPassword", "Email/Password Not Found");
            return View("Index");
        }

        HttpContext.Session.SetInt32("UserId", dbUser.UserId);
        return View("Success");
}


[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
public IActionResult Error()
{
    return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
}
}
