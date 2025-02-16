package com.kavindu.full_auth.repositoies;


import com.kavindu.full_auth.entities.AppUser;
import com.kavindu.full_auth.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshRepository extends JpaRepository<RefreshToken, Integer> {
    Optional<RefreshToken> findByRefreshToken(String token);
    RefreshToken findByUser(AppUser user);
    Optional<RefreshToken> findByUserEmail(String email);
    void delete(RefreshToken refreshToken);
}
