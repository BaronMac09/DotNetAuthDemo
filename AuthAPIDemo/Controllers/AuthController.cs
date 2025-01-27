using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace AuthAPIDemo.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    
    public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest model)
    {
        var user = new IdentityUser()
        {
            UserName = model.Email,
            Email = model.Email
        };
        
        var result = await _userManager.CreateAsync(user, model.Password);
        
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }
        
        var role = "User";
        if (model.Email.Contains("admin"))
        {
            role = "Admin";
        }
        
        if (!await _roleManager.RoleExistsAsync(role))
        {
            await _roleManager.CreateAsync(new IdentityRole(role));
        }

        // Assign the role to the user
        await _userManager.AddToRoleAsync(user, role);

        return Ok("Registered successfully");
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);

        if (user == null)
        {
            return BadRequest("User not found");
        }

        var result = await _userManager.CheckPasswordAsync(user, model.Password);
        if (!result) return BadRequest("Incorrect Credentials");
        
        var token = GenerateToken(user);
        return Ok(new {Token = token, Roles = await _userManager.GetRolesAsync(user)});
    }
    
    private async Task<string> GenerateToken(IdentityUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);
        
        // Create claims
        var claims = new List<Claim>()
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id)
        };
        
        // Add role claims
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        
        // Create the security key
        var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ThisIsASuperSecretKeyToGenerateTokensForAuthAPIDemoSecurity"));
        
        // Create the signing credentials
        var credentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

        // Create the token
        var token = new JwtSecurityToken(
            issuer: "https://localhost:5178",
            audience: "https://localhost:5178",
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: credentials
        );

        // Serialize the token
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}