package com.example.demo.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public String getRole(){
        return "hihi admin";
    }

    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public String postRole(){
        return "hihi create admin";
    }

    @PutMapping
    @PreAuthorize("hasAuthority('admin:update')")
    public String putRole(){
        return "hihi update admin";
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    public String deleteRole(){
        return "hihi delete admin";
    }

}
