package com.kavindu.full_auth.dto.Response;

import com.kavindu.full_auth.entities.Roles;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthResponse {
    private String token;
    private String username;
    private List<String> roles;

    public AuthResponse(String token, String username, Set<Roles> roles) {
        this.token = token;
        this.username = username;
        this.roles = roles.stream().map(Roles::getName).collect(Collectors.toList());
    }
}
