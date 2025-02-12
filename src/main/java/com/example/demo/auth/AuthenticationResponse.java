package com.example.demo.auth;

import lombok.Builder;

@Builder
public record AuthenticationResponse(
        String token

) {
}
