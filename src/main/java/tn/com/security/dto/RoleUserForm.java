package tn.com.security.dto;


import lombok.Data;

@Data
public class RoleUserForm {
  private String username;
  private String roleName;

  public RoleUserForm() {
  }

  public RoleUserForm(String username, String roleName) {
    this.username = username;
    this.roleName = roleName;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getRoleName() {
    return roleName;
  }

  public void setRoleName(String roleName) {
    this.roleName = roleName;
  }
}
