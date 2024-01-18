package tn.com.security.service;

import java.util.List;
import tn.com.security.entities.AppRole;
import tn.com.security.entities.AppUser;

public interface AccountService {

  AppUser addUser(AppUser user);
  AppRole addRole(AppRole role);
  void addRoleToUser(String username, String roleName);
  AppUser loadUserByUsername(String username);
  List<AppUser> listUser();
}
