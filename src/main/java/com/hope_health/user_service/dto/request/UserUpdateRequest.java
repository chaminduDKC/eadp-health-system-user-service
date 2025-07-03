package com.hope_health.user_service.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserUpdateRequest {
    private String email;
    private String name;
    private String address;
    private String phone;
    private String password;
    private String age;
    private String gender;
}
