package com.example.keycloak;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class ControllerKeycloak {

    @GetMapping
    @PreAuthorize("hasRole('Client_User')")
    public String hello(){
        return "hello keycloak";
    }
    @GetMapping("/hello-2")
    @PreAuthorize("hasRole('Client_Admin')")
    public String hello2(){
        return "hello keycloak - admin";
    }
}
