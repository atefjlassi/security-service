package tn.com.security.service;

import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tn.com.security.entities.AppRole;
import tn.com.security.entities.AppUser;
import tn.com.security.repository.AppRoleRepository;
import tn.com.security.repository.AppUserRepository;

@Service
@Slf4j
@Transactional
public class AccountServiceImpl implements AccountService {

  private final AppUserRepository appUserRepository;
  private final AppRoleRepository appRoleRepository;
  private final PasswordEncoder passwordEncoder;

  public AccountServiceImpl(AppUserRepository appUserRepository,
    AppRoleRepository appRoleRepository, PasswordEncoder passwordEncoder) {
    this.appUserRepository = appUserRepository;
    this.appRoleRepository = appRoleRepository;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public AppUser addUser(AppUser user) {
    String pwd = user.getPassword();
    user.setPassword(this.passwordEncoder.encode(pwd));
    return appUserRepository.save(user);
  }

  @Override
  public AppRole addRole(AppRole role) {
    return appRoleRepository.save(role);
  }

  @Override
  public void addRoleToUser(String username, String roleName) {
    AppUser user = appUserRepository.findByUsername(username);
    Optional<AppRole> role = appRoleRepository.findByRoleName(roleName);
    user.getAppRoles().add(role.get());
    this.addUser(user);
  }

  @Override
  public AppUser loadUserByUsername(String username) {
    AppUser app = this.appUserRepository.findByUsername(username);
    return app;
  }

  @Override
  public List<AppUser> listUser() {
    return this.appUserRepository.findAll();
  }
}
