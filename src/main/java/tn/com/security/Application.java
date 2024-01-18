package tn.com.security;

import java.util.ArrayList;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import tn.com.security.entities.AppRole;
import tn.com.security.entities.AppUser;
import tn.com.security.service.AccountService;

@Slf4j
@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class Application {

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

  @Bean
  CommandLineRunner start(AccountService accountService) {
    return args -> {

      log.info(" ### begin dumb users ###");

      accountService.addRole(new AppRole(null, "USER"));
      accountService.addRole(new AppRole(null, "ADMIN"));
      accountService.addRole(new AppRole(null, "CUSTOMER_MANAGER"));
      accountService.addRole(new AppRole(null, "PRODUCT_MANAGER"));
      accountService.addRole(new AppRole(null, "BILLS_MANAGER"));

      accountService.addUser(new AppUser(null, "user1", "@zerty1234", new ArrayList<>()));
      accountService.addUser(new AppUser(null, "admin", "@zerty1234", new ArrayList<>()));
      accountService.addUser(new AppUser(null, "user2", "@zerty1234", new ArrayList<>()));
      accountService.addUser(new AppUser(null, "user3", "@zerty1234", new ArrayList<>()));
      accountService.addUser(new AppUser(null, "user4", "@zerty1234", new ArrayList<>()));

      accountService.addRoleToUser("user1", "USER");
      accountService.addRoleToUser("admin", "ADMIN");
      accountService.addRoleToUser("user2", "USER");
      accountService.addRoleToUser("user2", "CUSTOMER_MANAGER");
      accountService.addRoleToUser("user3", "USER");
      accountService.addRoleToUser("user3", "PRODUCT_MANAGER");
      accountService.addRoleToUser("user4", "USER");
      accountService.addRoleToUser("user4", "BILLS_MANAGER");

      log.info(" ### end dumb users ###");

    };
  }


  @Bean
  public static PasswordEncoder passwordEncoder() {
//    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    return new BCryptPasswordEncoder();
//    return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
  }

}
