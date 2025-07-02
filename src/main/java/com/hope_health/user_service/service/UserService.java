package com.hope_health.user_service.service;

import com.hope_health.user_service.dto.request.UserLoginRequest;
import com.hope_health.user_service.dto.request.UserRequestDto;
import com.hope_health.user_service.dto.request.UserUpdateRequest;
import com.hope_health.user_service.dto.response.UserResponseDto;
import org.springframework.stereotype.Service;

@Service
public interface UserService {
    UserResponseDto createPatient(UserRequestDto request);
    UserResponseDto createDoctor(UserRequestDto request);

    Object login(UserLoginRequest request);

    boolean verifyUser(String email, String otp);

    boolean resendOtp(String email);

    Object getUserById(String userId);

    void updateUser(String userId, UserUpdateRequest request);

    Boolean deleteUser(String userId);
}
