package com.example.instazoo.payload.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class LoginRequest {
        @NotEmpty(message = "Username can not be empty")
        private String username;
         @NotEmpty(message = "Username can not be empty")
        private String password;
}
