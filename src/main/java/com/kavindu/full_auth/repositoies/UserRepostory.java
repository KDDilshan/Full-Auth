package com.kavindu.full_auth.repositoies;

import com.kavindu.full_auth.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepostory extends JpaRepository<AppUser, Integer> {
    Optional<AppUser> findByEmail(String email);
}
