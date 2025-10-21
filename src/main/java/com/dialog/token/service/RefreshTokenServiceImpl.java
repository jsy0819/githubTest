package com.dialog.token.service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.dialog.token.domain.RefreshToken;
import com.dialog.token.repository.RefreshTokenRepository;
import com.dialog.user.domain.MeetUser;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {

    // JPA 리파지토리를 통해 DB의 refresh_token 테이블에 접근
    private final RefreshTokenRepository refreshTokenRepository;
    
    // 리프레시 토큰 기본 유효기간: 7일 (밀리초 단위, 사용 시 LocalDateTime 등으로 변환됨)
    private final long refreshTokenDurationMs = 7 * 24 * 60 * 60 * 1000L; // 7일

    // 1. 리프레시 토큰 생성: 사용자 객체를 받아서 랜덤 UUID 토큰 생성 후 DB에 저장
    @Override
    public RefreshToken createRefreshToken(MeetUser user) {
        // 리프레시 토큰 문자열 생성(UUID: 충돌 가능성 극히 낮은 랜덤 ID)
        String token = UUID.randomUUID().toString();

        // 현재 시각 발급 시각
        LocalDateTime issuedAt = LocalDateTime.now();
        // 발급 시각으로부터 7일 후 만료 시각
        LocalDateTime expiresAt = issuedAt.plusDays(7);

        // 엔티티 빌더를 사용해 리프레시 토큰 객체 생성
        RefreshToken refreshToken = RefreshToken.builder()
                .refreshToken(token)        // 실제 토큰 문자열 세팅
                .issuedAt(issuedAt)          // 발급 시각 세팅
                .expiresAt(expiresAt)        // 만료 시각 세팅
                .revoked(false)              // 초기 상태는 폐기 상태 아님
                .user(user)                  // 토큰 소유자 연결
                .build();

        // DB에 저장 후 저장된 엔티티 반환
        return refreshTokenRepository.save(refreshToken);
    }

    // 2. 토큰 문자열로 DB에서 리프레시 토큰 조회
    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByRefreshToken(token);
    }

    // 3. 토큰 유효성 검증: 존재 여부, 폐기 상태, 만료 여부 확인
    @Override
    public RefreshToken verifyTokenValidity(String token) {
        // DB에서 토큰 조회, 없으면 예외 발생
        RefreshToken refreshToken = findByToken(token)
                .orElseThrow(() -> new RuntimeException("리프레시 토큰이 존재하지 않습니다."));

        // 폐기된 토큰인지 체크 후 예외 발생
        if (refreshToken.isRevoked()) {
            throw new RuntimeException("리프레시 토큰이 폐기되었습니다.");
        }

        // 만료된 토큰인지 체크 후 예외 발생
        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("리프레시 토큰이 만료되었습니다.");
        }

        // 모든 검사 통과하면 해당 토큰 리턴
        return refreshToken;
    }

    // 4. 토큰 폐기 처리: 토큰을 찾아 revoked=true 로 표시하고 DB 업데이트
    @Override
    public void revokeToken(String token) {
        findByToken(token).ifPresent(rt -> {
            rt.setRevoked(true);                // 폐기 상태로 상태 변경
            refreshTokenRepository.save(rt);   // 저장소에 변경 상태 반영
            log.info("리프레시 토큰이 폐기되었습니다.");
        });
    }

    // 5. 만료된 토큰 정리: 현재 시각 이전에 만료된 모든 토큰을 DB에서 삭제
    @Override
    @Transactional
    public void deleteExpiredTokens() {
        refreshTokenRepository.deleteByExpiresAtBefore(LocalDateTime.now());
        log.info("만료된 리프레시 토큰 정리 완료");
    }
}