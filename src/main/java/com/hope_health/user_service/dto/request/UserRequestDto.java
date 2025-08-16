package com.hope_health.user_service.dto.request;

import lombok.*;

import java.time.LocalDate;
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
    private String userId;
    private String password;
    private String address;
    private String phone;
    private String age;
    private String gender;
    private LocalDate createdDate;
    private String role;
    private String specialization;
    private String experience;
    private String hospital;
    private String licenceNo;
    private String city;

}
