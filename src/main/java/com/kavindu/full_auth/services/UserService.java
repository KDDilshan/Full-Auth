package com.kavindu.full_auth.services;

import com.kavindu.full_auth.dto.Request.LoginDto;
import com.kavindu.full_auth.dto.Request.RegisterDto;
import com.kavindu.full_auth.dto.Response.AuthResponse;
import com.kavindu.full_auth.entities.AppUser;
import com.kavindu.full_auth.entities.Roles;
import com.kavindu.full_auth.repositoies.RoleRepository;
import com.kavindu.full_auth.repositoies.UserRepostory;
import com.kavindu.full_auth.security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Service
public class UserService {
    private final UserRepostory userRepostory;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;

    public UserService(UserRepostory userRepostory, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, RoleRepository roleRepository, JwtService jwtService) {
        this.userRepostory = userRepostory;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.roleRepository = roleRepository;
        this.jwtService = jwtService;
    }

    public AppUser registerUser(RegisterDto request) {

        Roles role = roleRepository.findByName("ROLE_USER").orElseThrow(() -> new RuntimeException("Role not found"));
        AppUser user = new AppUser();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEmail(request.getEmail());

        user.setRoles(Set.of(role));
        return userRepostory.save(user);
    }

    public AppUser registerAdmin(RegisterDto request) {
        Roles role =roleRepository.findByName("ROLE_ADMIN").orElseThrow(() -> new RuntimeException("Role not found"));
        AppUser user = new AppUser();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEmail(request.getEmail());
        user.setRoles(Set.of(role));
        return userRepostory.save(user);
    }

    public AuthResponse loginUser(LoginDto request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        AppUser user = (AppUser) authentication.getPrincipal();

        System.out.println("user: " + user);
        String token = jwtService.generateToken(user);

        return new AuthResponse(token, user.getUsername(), user.getRoles());
    }






}
