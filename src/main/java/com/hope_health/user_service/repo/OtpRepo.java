package com.hope_health.user_service.repo;

import com.hope_health.user_service.entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OtpRepo extends JpaRepository<Otp, String> {
    public Optional<Otp> findByUserUserId(String id);
}
