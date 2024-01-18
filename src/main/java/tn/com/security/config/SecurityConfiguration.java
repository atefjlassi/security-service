package tn.com.security.config;

import java.util.ArrayList;
import java.util.Collection;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tn.com.security.entities.AppUser;
import tn.com.security.filters.AuthenticationFilter;
import tn.com.security.filters.JwtAuthorizationFilter;
import tn.com.security.service.AccountService;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

  private final AccountService accountService;
  private final PasswordEncoder passwordEncoder;

  public SecurityConfiguration(AccountService accountService, PasswordEncoder passwordEncoder) {
    this.accountService = accountService;
    this.passwordEncoder = passwordEncoder;
  }

  // this configure method for telling spring the source from where you should take/get Users
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    // search the user from our business logic service
    UserDetailsService userDetailsService = this.getUserDetailsService();
    auth.userDetailsService(userDetailsService).passwordEncoder(this.passwordEncoder);
  }

  private UserDetailsService getUserDetailsService() {
    UserDetailsService userDetailsService = username -> {
      AppUser appUser = accountService.loadUserByUsername(username);
      log.info("**** loadUserByUsername ****");
      log.info("Logging appUser : {}", appUser);
      Collection<GrantedAuthority> authorities = new ArrayList<>();
      appUser.getAppRoles()
        .forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getRoleName())));

      log.info("Logging appUser with GrantedAuthority : {}", appUser);
      UserDetails user = new User(appUser.getUsername(), appUser.getPassword(), authorities);
      log.info("Logging spring User() : {}", user.getPassword());
      return user;
    };

    return userDetailsService;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    log.info(" ### Logging HttpSecurity Configuration ###");

    http.csrf().disable();
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    http.headers().frameOptions().disable();
    http.authorizeRequests().antMatchers("/login/**", "/refreshToken/**").permitAll()
      .antMatchers("/h2-console/**").permitAll();

/*  The classic way to secure resources, otherwise we can use annotations.

    http.authorizeRequests().antMatchers(HttpMethod.POST, "/users/**").hasAuthority("ADMIN");
    http.authorizeRequests().antMatchers(HttpMethod.POST, "/addRoleToUser/**").hasAuthority("ADMIN");
    http.authorizeRequests().antMatchers(HttpMethod.GET, "/users/**").hasAnyAuthority("USER", "ADMIN");
*/

    http.authorizeRequests().anyRequest().authenticated();

    http.addFilter(new AuthenticationFilter(authenticationManagerBean()));
    http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManager();
  }

}
