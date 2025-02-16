package com.kavindu.full_auth.controllers;

import com.kavindu.full_auth.dto.Request.LoginDto;
import com.kavindu.full_auth.dto.Request.RegisterDto;
import com.kavindu.full_auth.dto.Request.TokenRequest;
import com.kavindu.full_auth.dto.Response.AuthResponse;
import com.kavindu.full_auth.entities.AppUser;
import com.kavindu.full_auth.security.JwtService;
import com.kavindu.full_auth.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
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
@RequestMapping("/auth/api/")
public class AuthController {
    private final JwtService jwtService;
    private final UserService userService;

    public AuthController(final JwtService jwtService, final UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> RegisterUser(@RequestBody RegisterDto registerDto) {
        try{
            AppUser registeredUser=userService.registerUser(registerDto);
            return ResponseEntity.ok(registeredUser);
        }catch (Exception e){
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }

    }

    @PostMapping("/login")
    public ResponseEntity<?> LoginUser(@RequestBody LoginDto loginDto) {
        try{
            return ResponseEntity.ok(userService.loginUser(loginDto));
        }catch (Exception e){
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    @PostMapping("/Admin_Register")
    public ResponseEntity<?> RegisterAdmin(@RequestBody RegisterDto registerDto) {
        try{
            AppUser registerdAdmin=userService.registerAdmin(registerDto);
            return ResponseEntity.ok(registerdAdmin);
        }catch (Exception e){
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    @PostMapping("/Refresh")
    public ResponseEntity<?> getAcessToken(@RequestBody TokenRequest request) {
        try {
            String refreshToken=request.getRefreshToken();
            if(refreshToken==null){
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("refresh token is null");
            }
            Map<String,String> tokens=userService.getAccessToken(refreshToken);
            return ResponseEntity.ok(tokens);
        }catch (Exception e){
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    @PostMapping("/Logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try{
            userService.logout(request);
            Map<String,String> response=new HashMap<>();
            response.put("message","user logout Successfully");
            return ResponseEntity.status(HttpStatus.OK).body(response);
        }catch (Exception e){
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }


}
