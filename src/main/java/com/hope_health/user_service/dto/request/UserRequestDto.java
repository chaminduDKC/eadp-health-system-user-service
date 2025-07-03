package com.hope_health.user_service.dto.request;

import lombok.*;

import java.util.Date;
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class UserRequestDto {
    private String email;
    private String name;
    private String password;
    private String userId;
    private String address;
    private String phone;
    private String age;
    private String gender;
    private Date createdDate;
    private String role;
}
