package com.hope_health.user_service.dto.response;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserResponseDto {
    private String userId;
    private String FirstName;
    private String lastName;
    private String email;
    private boolean isEmailVerified;

}
