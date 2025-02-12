package com.example.demo.auth;

import lombok.Data;
import lombok.Getter;

public record AuthenticationRequest(
        String email,
        String password
) {
}
