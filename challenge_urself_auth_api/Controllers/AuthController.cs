using Google.Apis.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using challenge_urself_auth_api.Models;
using challenge_urself_auth_api.Services;

namespace challenge_urself_auth_api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IConfiguration _configuration;

    public AuthController(IJwtTokenService jwtTokenService, IConfiguration configuration)
    {
        _jwtTokenService = jwtTokenService;
        _configuration = configuration;
    }

    /// <summary>
    /// Exchange a Google ID token for a JWT. Call this from your UI after the user signs in with Google.
    /// </summary>
    /// <param name="request">Request body containing the Google ID token from the client.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Access token (JWT), expiry, and user info for the UI to store and use.</returns>
    [HttpPost("google")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> LoginWithGoogle([FromBody] GoogleLoginRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.IdToken))
            return BadRequest(new { error = "IdToken is required." });

        var googleClientId = _configuration["Google:ClientId"];
        if (string.IsNullOrEmpty(googleClientId))
            return StatusCode(500, new { error = "Google:ClientId is not configured." });

        GoogleJsonWebSignature.Payload payload;
        try
        {
            var validationSettings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new[] { googleClientId }
            };
            payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, validationSettings);
        }
        catch (InvalidJwtException ex)
        {
            return BadRequest(new { error = "Invalid Google ID token.", detail = ex.Message });
        }

        var (accessToken, expiresAt) = _jwtTokenService.GenerateToken(
            payload.Subject,
            payload.Email ?? string.Empty,
            payload.Name
        );

        var response = new LoginResponse(
            AccessToken: accessToken,
            ExpiresAt: expiresAt,
            User: new UserInfo(
                Sub: payload.Subject,
                Email: payload.Email ?? string.Empty,
                Name: payload.Name
            )
        );

        return Ok(response);
    }

    /// <summary>
    /// Returns the current user from the JWT. Use the token from LoginWithGoogle in the Authorization header.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType(typeof(UserInfo), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult GetCurrentUser()
    {
        var sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                  ?? User.FindFirst("sub")?.Value;
        var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                   ?? User.FindFirst("email")?.Value;
        var name = User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value
                   ?? User.Identity?.Name;

        if (string.IsNullOrEmpty(sub))
            return Unauthorized();

        return Ok(new UserInfo(Sub: sub, Email: email ?? string.Empty, Name: name));
    }
}
