package com.kavindu.full_auth.services;

import com.kavindu.full_auth.dto.Request.LoginDto;
import com.kavindu.full_auth.dto.Request.RegisterDto;
import com.kavindu.full_auth.entities.AppUser;
import com.kavindu.full_auth.repositoies.UserRepostory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {
    private final UserRepostory userRepostory;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;


    public UserService(UserRepostory userRepostory, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userRepostory = userRepostory;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public AppUser signup(RegisterDto input) {
        AppUser user = new AppUser();
        user.setUsername(input.getUsername());
        user.setPassword(passwordEncoder.encode(input.getPassword()));
        user.setEmail(input.getEmail());

        return userRepostory.save(user);
    }

    public AppUser authenticate(LoginDto loginDto) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginDto.getEmail(),
                        loginDto.getPassword()
                )
        );

        return userRepostory.findByEmail(loginDto.getEmail())
                .orElse(null);
    }


    public List<AppUser> allUsers() {
         List<AppUser> users=new ArrayList<>();
         userRepostory.findAll().forEach(users::add);
         return users;
    }
}
