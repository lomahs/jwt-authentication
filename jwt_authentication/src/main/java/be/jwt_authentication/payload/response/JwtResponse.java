package be.jwt_authentication.payload.response;

import be.jwt_authentication.models.Role;
import lombok.*;

import java.util.List;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponse {

    private String accessToken;

    private String type = "Bearer";

    private String refreshToken;

    private Long id;

    private String username;

    private String email;

    private List<String> roles;

    public JwtResponse(String accessToken, Long id, String username, String email, List<String> roles) {
        this.accessToken = accessToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    public JwtResponse(String token, String refreshToken, Long id, String username, String email, List<String> roles) {
        this.accessToken = token;
        this.refreshToken = refreshToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }
}