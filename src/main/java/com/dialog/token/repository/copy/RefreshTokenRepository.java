package com.dialog.token.repository.copy;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dialog.token.domain.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByRefreshToken(String refreshToken);
    
    List<RefreshToken> findByUserId(Long userId);
    
    void deleteByExpiresAtBefore(LocalDateTime now); // 만료된 토큰 삭제용
}
