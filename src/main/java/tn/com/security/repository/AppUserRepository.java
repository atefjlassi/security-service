package tn.com.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tn.com.security.entities.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, String> {
  AppUser findByUsername(String username);
}
