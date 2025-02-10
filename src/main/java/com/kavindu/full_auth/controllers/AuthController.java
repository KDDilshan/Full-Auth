package com.kavindu.full_auth.controllers;

import com.kavindu.full_auth.dto.Request.LoginDto;
import com.kavindu.full_auth.dto.Request.RegisterDto;
import com.kavindu.full_auth.dto.Response.AuthResponse;
import com.kavindu.full_auth.entities.AppUser;
import com.kavindu.full_auth.security.JwtService;
import com.kavindu.full_auth.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.SQLOutput;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth/")
public class AuthController {
    private final JwtService jwtService;
    private final UserService userService;

    public AuthController(final JwtService jwtService, final UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> RegisterUser(@RequestBody RegisterDto registerDto) {
        try{
            System.out.println(registerDto);
            AppUser registeredUser=userService.signup(registerDto);
            return ResponseEntity.ok(registeredUser);
        }catch (Exception e){
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }

    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> LoginUser(@RequestBody LoginDto loginDto) {
        AppUser authenticatedUser=userService.authenticate(loginDto);

        String token = jwtService.generateToken(authenticatedUser);

        AuthResponse authResponse=new AuthResponse();
        authResponse.setToken(token);
        authResponse.setExpiresIn(jwtService.getJwtExpirationTime());
        return ResponseEntity.ok(authResponse);
    }
}
