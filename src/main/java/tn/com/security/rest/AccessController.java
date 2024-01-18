package tn.com.security.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import tn.com.security.entities.AppRole;
import tn.com.security.entities.AppUser;
import tn.com.security.service.AccountService;
import tn.com.security.utils.SecurityUtils;

@RestController
public class AccessController {

  private final AccountService accountService;

  public AccessController(AccountService accountService) {
    this.accountService = accountService;
  }

  // get the refreshToken and use it to generate a new access-token
  @GetMapping(path = "/refreshToken")
  public void refreshToken(HttpServletRequest request, HttpServletResponse response)
    throws IOException {
    String authenticationToken = request.getHeader("Authorization");

    if (authenticationToken != null && authenticationToken.startsWith("Bearer ")) {
      try {
        String refreshToken = authenticationToken.substring(7);
        Algorithm algorithm = Algorithm.HMAC256(SecurityUtils.PRIVATE_SECRET);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(refreshToken);
        String username = decodedJWT.getSubject();

        AppUser appUser = this.accountService.loadUserByUsername(username);
        String jwtAccessToken = JWT.create()
          .withSubject(appUser.getUsername())
          .withExpiresAt(new Date(System.currentTimeMillis() + 1 * 60 * 1000))
          .withIssuer(request.getRequestURL()
            .toString())  // issuer: le nom de l'application qui a générer le token = url de la request
          .withClaim("roles", appUser.getAppRoles().stream().map(AppRole::getRoleName)
            .collect(Collectors.toList()))       // private claims
          .sign(algorithm);      // last thing, set algorithm

        Map<String, String> idToken = new HashMap<>();
        idToken.put("access-token", jwtAccessToken);
        idToken.put("refresh-token", refreshToken);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), idToken);

      } catch (Exception e) {
        throw e;
      }
    } else {
      throw new RuntimeException("Refresh token required");
    }
  }

}
