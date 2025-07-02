package com.hope_health.user_service.controller;

import com.hope_health.user_service.dto.request.UserLoginRequest;
import com.hope_health.user_service.dto.request.UserRequestDto;
import com.hope_health.user_service.dto.request.UserUpdateRequest;
import com.hope_health.user_service.service.UserService;
import com.hope_health.user_service.util.StandardResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/test")
    public String test(){
        return "Working";
    }

    @PostMapping("/admin-login")
    @PreAuthorize("hasRole('admin')")
    public ResponseEntity<StandardResponse> adminLogin(@RequestBody UserLoginRequest request){
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(200)
                        .message("Admin logged in successfully")
                        .data(userService.login(request))
                        .build(),
                HttpStatus.OK
        );
    }


    //================================================================

    @PostMapping("/register-patient")
    public ResponseEntity<StandardResponse> registerPatient(@RequestBody UserRequestDto request){
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(201)
                        .message("User[patient] created success")
                        .data( userService.createPatient(request))
                        .build(),
                HttpStatus.CREATED
                );
    }

    @PostMapping("/register-doctor")
    @PreAuthorize("hasRole('admin')")
    public ResponseEntity<StandardResponse> registerDoctor(@RequestBody UserRequestDto request){
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(201)
                        .message("User[doctor] created success")
                        .data(userService.createDoctor(request))
                        .build(),
                HttpStatus.CREATED
        );
    }

    @PostMapping("/verify-user")
    public ResponseEntity<StandardResponse> verifyUser(@RequestParam String email, String otp){
        boolean isVerified = userService.verifyUser(email, otp);
        if(isVerified){
            return new ResponseEntity<>(
                    StandardResponse.builder()
                            .code(200)
                            .message("User verified success")
                            .data(null)
                            .build(),
                    HttpStatus.OK
            );
        } else {
            return new ResponseEntity<>(
                    StandardResponse.builder()
                            .code(400)
                            .message("User not verified, enter correct credentials")
                            .data(null)
                            .build(),
                    HttpStatus.BAD_REQUEST
            );
        }
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<StandardResponse> resendOtp(@RequestParam String email){
        boolean isVerified = userService.resendOtp(email);
        if(isVerified){
            return new ResponseEntity<>(
                    StandardResponse.builder()
                            .code(200)
                            .message("User verified success")
                            .data(null)
                            .build(),
                    HttpStatus.OK
            );
        } else {
            return new ResponseEntity<>(
                    StandardResponse.builder()
                            .code(400)
                            .message("User not verified, enter correct credentials")
                            .data(null)
                            .build(),
                    HttpStatus.BAD_REQUEST
            );
        }
    }

    @PostMapping("/doctor-login")
    public ResponseEntity<StandardResponse> loginDoctor(@RequestBody UserLoginRequest request){
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(201)
                        .message("User[doctor] logged success")
                        .data(userService.login(request))
                        .build(),
                HttpStatus.CREATED
        );
    }

    @PostMapping("/patient-login")
    public ResponseEntity<StandardResponse> loginPatient(@RequestBody UserLoginRequest request){
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(201)
                        .message("User[patient] logged success")
                        .data(userService.login(request))
                        .build(),
                HttpStatus.CREATED
        );
    }

    @PreAuthorize("hasRole('doctor')")
    @GetMapping("/{userId}")
    public ResponseEntity<StandardResponse> getUserById(@PathVariable String userId) {
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(200)
                        .message("User retrieved Success")
                        .data(userService.getUserById(userId))
                        .build(),
                HttpStatus.OK
        );
    }

    @PutMapping("/update-user/{userId}")
    public ResponseEntity<StandardResponse> updateUser(@PathVariable String userId, @RequestBody UserUpdateRequest request) {
        System.out.println(request);
        userService.updateUser(userId, request);
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(200)
                        .message("User updated Success")
                        .data(null)
                        .build(),
                HttpStatus.OK
        );
    }

    @PreAuthorize("hasRole('admin')")
    @DeleteMapping("/delete-user/{userId}")
    public ResponseEntity<StandardResponse> deleteUser(@PathVariable String userId) {
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(200)
                        .message("User deleted Success")
                        .data(userService.deleteUser(userId))
                        .build(),
                HttpStatus.NO_CONTENT
        );
    }

    // Role-based filtering
    @PreAuthorize("hasRole('admin')")
    @GetMapping("/roles/{role}")
    public ResponseEntity<StandardResponse> getUsersByRole(@PathVariable String role) {
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(200)
                        .message("User retrieved by role"+ role)
                        .data(null)
                        .build(),
                HttpStatus.NO_CONTENT
        );

    }

    // Search
    @PreAuthorize("hasRole('admin')")
    @GetMapping("/search")
    public ResponseEntity<StandardResponse> searchUsers(@RequestParam String name) {
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(200)
                        .message("User are searching")
                        .data(null)
                        .build(),
                HttpStatus.NO_CONTENT
        );
    }

    // Self Profile
    @GetMapping("/me")
    public ResponseEntity<StandardResponse> getCurrentUser(Authentication auth) {
        return new ResponseEntity<>(
                StandardResponse.builder()
                        .code(200)
                        .message("Current User")
                        .data(null)
                        .build(),
                HttpStatus.NO_CONTENT
        );
    }

    //================================================================
}
