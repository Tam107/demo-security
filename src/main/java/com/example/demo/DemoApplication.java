package com.example.demo;

import com.example.demo.auth.AuthenticationService;
import com.example.demo.auth.RegisterRequest;
import com.example.demo.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.example.demo.user.Role.ADMIN;
import static com.example.demo.user.Role.MANAGER;

@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(AuthenticationService service){

        return args -> {
          var admin = RegisterRequest.builder()
                  .firstname("Admin")
                  .lastname("admin")
                  .email("admin@email.com")
                  .password("password")
                  .role(ADMIN)
                  .build();
            System.out.println("Admin token: "+service.register(admin).accessToken());

            var manager = RegisterRequest.builder()
                  .firstname("MANAGER")
                  .lastname("manager")
                  .email("manager@email.com")
                  .password("password")
                  .role(MANAGER)
                  .build();
            System.out.println("MANAGER token: "+service.register(manager).accessToken());
        };

    }

}
