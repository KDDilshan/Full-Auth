package com.kavindu.full_auth.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/")
public class SecureController {

    @GetMapping("/get")
    public String get() {
        return "You are in Admin World";
    }
}
