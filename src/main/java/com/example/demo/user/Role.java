package com.example.demo.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.demo.user.Permission.*;

@RequiredArgsConstructor
public enum Role {

    USER(Collections.emptySet()),
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_UPDATE,
                    ADMIN_DELETE,
                    ADMIN_CREATE,
                    MANAGER_DELETE,
                    MANAGER_CREATE,
                    MANAGER_UPDATE,
                    MANAGER_READ
            )
    ),
    MANAGER(
            Set.of(
                    MANAGER_DELETE,
                    MANAGER_CREATE,
                    MANAGER_UPDATE,
                    MANAGER_READ)
    );

    // dont have duplicate permission
    @Getter
    private final Set<Permission> permission;


    public List<SimpleGrantedAuthority> getAuthorities(){
        var authorities = getPermission().stream().map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());

        // auto configure by spring
        authorities.add(new SimpleGrantedAuthority("ROLE_"+ this.name()));

        return authorities;
    }
}
