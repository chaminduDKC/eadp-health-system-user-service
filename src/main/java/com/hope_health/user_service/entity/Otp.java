package com.hope_health.user_service.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Entity
@Table(name = "otp")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class Otp {
    @Id
    @Column(name = "otp_id", nullable = false, unique = true)
    private String otpId;

    @Column(name = "code", nullable = false, length = 10)
    private String code;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", columnDefinition = "DATETIME", nullable = false)
    private Date createdDate;

    @Column(name = "is_verified", nullable = false, columnDefinition = "TINYINT")
    private Boolean isVerified;

    @Column(name = "attempts", nullable = false)
    private Integer attempts;

    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.REMOVE)
    @JoinColumn(name = "user_otp_id", referencedColumnName = "user_id", nullable = false)
    private UserEntity user;
}
