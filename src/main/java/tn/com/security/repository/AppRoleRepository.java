package tn.com.security.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import tn.com.security.entities.AppRole;

public interface AppRoleRepository extends JpaRepository<AppRole, String> {

  Optional<AppRole> findByRoleName(String roleName);
}
