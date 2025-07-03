package com.hope_health.user_service.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Entity
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class UserEntity {
    @Id
    @Column(name = "user_id", nullable = false, unique = true)
    private String userId;

    @Column(name = "active_state", columnDefinition = "TINYINT", nullable = false)
    private Boolean activeState;

    @Column(name = "email", unique = true, length = 250, nullable = false)
    private String email;

    private String name;

    @Column(name = "is_account_non_expired", columnDefinition = "TINYINT", nullable = false)
    private Boolean isAccountNonExpired;

    @Column(name = "is_email_verified", columnDefinition = "TINYINT", nullable = false)
    private Boolean isEmailVerified;

    @Column(name = "is_account_non_locked", columnDefinition = "TINYINT", nullable = false)
    private Boolean isAccountNonLocked;

    @Column(name = "is_enabled", columnDefinition = "TINYINT", nullable = false)
    private Boolean isEnabled;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, columnDefinition = "DATETIME")
    private Date createdDate;

    @OneToOne(mappedBy = "user", fetch = FetchType.EAGER, cascade = CascadeType.REMOVE)
    private Otp otp;

    private String role;

}
