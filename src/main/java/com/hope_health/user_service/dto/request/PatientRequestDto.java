package com.hope_health.user_service.dto.request;

import lombok.*;

import java.util.Date;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class PatientRequestDto {
    private String email;
    private String userId;
    private String name;
    private String password;
    private String address;
    private String phone;
    private String age;
    private String gender;
    private Date createdDate;
    private String role;
}
