package be.jwt_authentication.payload.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LogOutRequest {
    private Long userId;
}