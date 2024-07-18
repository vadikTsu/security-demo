package com.vadik;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
public class Controller {

    @GetMapping("/protected")
    public ResponseEntity<?> getProtectedResource(){
        var message = new HashMap<>();
        message.put("message", "nice job, you are at protected source");
        return ResponseEntity.ok().body(message);
    }

    @RequestMapping("/Login")
    public ResponseEntity<?> getUserDetailsAfterLogin(Authentication authentication) {
        return ResponseEntity.status(200).build();
    }
}
