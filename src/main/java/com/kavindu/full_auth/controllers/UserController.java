package com.kavindu.full_auth.controllers;

import com.kavindu.full_auth.entities.AppUser;
import com.kavindu.full_auth.services.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public ResponseEntity<AppUser> getCurrentUser() {
        Authentication authentication= SecurityContextHolder.getContext().getAuthentication();
        AppUser currentUser=(AppUser) authentication.getPrincipal();
        return ResponseEntity.ok(currentUser);
    }

    @GetMapping("/")
    public ResponseEntity<List<AppUser>> getAllUsers() {
        List<AppUser> users=userService.allUsers();
        return ResponseEntity.ok(users);
    }
}
