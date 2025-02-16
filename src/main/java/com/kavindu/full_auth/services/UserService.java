package com.kavindu.full_auth.services;

import com.kavindu.full_auth.dto.Request.LoginDto;
import com.kavindu.full_auth.dto.Request.RegisterDto;
import com.kavindu.full_auth.dto.Response.AuthResponse;
import com.kavindu.full_auth.entities.AppUser;
import com.kavindu.full_auth.entities.RefreshToken;
import com.kavindu.full_auth.entities.Roles;
import com.kavindu.full_auth.repositoies.RefreshRepository;
import com.kavindu.full_auth.repositoies.RoleRepository;
import com.kavindu.full_auth.repositoies.UserRepostory;
import com.kavindu.full_auth.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class UserService {
    private final UserRepostory userRepostory;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final RefreshRepository refreshRepository;

    public UserService(UserRepostory userRepostory, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, RoleRepository roleRepository, JwtService jwtService, RefreshRepository refreshRepository) {
        this.userRepostory = userRepostory;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.roleRepository = roleRepository;
        this.jwtService = jwtService;
        this.refreshRepository = refreshRepository;
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
        String RefreshToken=jwtService.generateRefreshToken(user);

        RefreshToken exsitingRefreshToken=refreshRepository.findByUser(user);
        if(exsitingRefreshToken !=null){
            exsitingRefreshToken.setRefreshToken(RefreshToken);
            exsitingRefreshToken.setExpiresIn(System.currentTimeMillis()+7*24*60*60*1000);
            refreshRepository.save(exsitingRefreshToken);
        }else{
            RefreshToken rToken=new RefreshToken();
            rToken.setRefreshToken(RefreshToken);
            rToken.setUser(user);
            rToken.setExpiresIn(System.currentTimeMillis() + 7*24*60*60*1000);
            refreshRepository.save(rToken);
        }

        return new AuthResponse(token,RefreshToken, user.getUsername(), user.getRoles());
    }


    public Map<String, String> getAccessToken(String refreshToken) {
        RefreshToken refreshToken1=refreshRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not present"));

        if(refreshToken1.getExpiresIn()<System.currentTimeMillis()){
            throw  new RuntimeException("Refresh token expired");
        }
        AppUser user=refreshToken1.getUser();
        String accessToken=jwtService.generateToken(user);

        Map<String,String> tokens=new HashMap<>();
        tokens.put("access_token",accessToken);
        tokens.put("refresh_token",refreshToken);
        return tokens;
    }

    public void logout(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            System.out.println("User is not authenticated.");
            return;
        }

        String email = authentication.getName(); // Get email
        System.out.println("Logging out user: " + email);

        request.getSession().invalidate();

        RefreshToken refreshToken = refreshRepository.findByUserEmail(email).orElse(null);
        if (refreshToken != null) {
            AppUser user = refreshToken.getUser();
            if (user != null) {
                user.setRefreshToken(null);
                userRepostory.save(user);
            }

            refreshRepository.delete(refreshToken);
            System.out.println("Refresh token deleted for user: " + email);
        } else {
            System.out.println("No refresh token found for user: " + email);
        }
        SecurityContextHolder.clearContext();
    }

}
