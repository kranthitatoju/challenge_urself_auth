namespace challenge_urself_auth_api.Services;

public interface IJwtTokenService
{
    (string AccessToken, DateTime ExpiresAt) GenerateToken(string subject, string email, string? name);
}
