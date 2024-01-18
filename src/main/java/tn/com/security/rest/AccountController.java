package tn.com.security.rest;

import java.util.List;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import tn.com.security.dto.RoleUserForm;
import tn.com.security.entities.AppRole;
import tn.com.security.entities.AppUser;
import tn.com.security.service.AccountService;

@RestController
public class AccountController {

  private final AccountService accountService;

  public AccountController(AccountService accountService) {
    this.accountService = accountService;
  }

  @GetMapping(path = "/users")
  @PostAuthorize("hasAnyAuthority('ADMIN', 'USER')")
  public List<AppUser> usersList() {
    return accountService.listUser();
  }

  @PostMapping(path = "/users")
  @PostAuthorize("hasAuthority('ADMIN')")
  public AppUser saveUser(@RequestBody AppUser user) {
    return accountService.addUser(user);
  }

  @PostMapping(path = "/users/addRole")
  @PostAuthorize("hasAuthority('ADMIN')")
  public AppRole saveRole(@RequestBody AppRole role) {
    return accountService.addRole(role);
  }

  @PostMapping(path = "/addRoleToUser")
  @PostAuthorize("hasAuthority('ADMIN')")
  public void addRoleToUser(@RequestBody RoleUserForm roleUserForm) {
    accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
  }

}
