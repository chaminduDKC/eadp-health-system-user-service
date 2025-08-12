package com.hope_health.user_service.dto.request;

import lombok.*;

import java.util.Date;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class DoctorRequestDto {
    private String userId;
    private String name;
    private String email;
    private String phoneNumber;
    private String specialization;
    private String experience;
    private String hospital;
    private String address;
    private String licenceNo;
    private String city;
}
