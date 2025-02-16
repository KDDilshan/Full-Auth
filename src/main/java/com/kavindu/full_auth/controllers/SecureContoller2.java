package com.kavindu.full_auth.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user/")
public class SecureContoller2 {

    @GetMapping("/get")
    public String get() {
        System.out.println("on");
        return "Both Admin and User can acess this  World";
    }
}
