namespace challenge_urself_auth_api.Models;

public record LoginResponse(
    string AccessToken,
    DateTime ExpiresAt,
    UserInfo User
);

public record UserInfo(string Sub, string Email, string? Name);
