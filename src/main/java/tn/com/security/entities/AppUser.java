package tn.com.security.entities;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;
import java.util.ArrayList;
import java.util.Collection;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@NoArgsConstructor @AllArgsConstructor @ToString
public class AppUser {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private String id;
  private String username;
  @JsonProperty(access = Access.WRITE_ONLY)
  @Column(length = 255)
  private String password;
  @ManyToMany(fetch = FetchType.EAGER)
  private Collection<AppRole> appRoles = new ArrayList<>();

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public Collection<AppRole> getAppRoles() {
    return appRoles;
  }

  public void setAppRoles(Collection<AppRole> appRoles) {
    this.appRoles = appRoles;
  }
}
