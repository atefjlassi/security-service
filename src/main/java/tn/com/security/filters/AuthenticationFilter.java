package tn.com.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tn.com.security.utils.SecurityUtils;

@Slf4j
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;

  public AuthenticationFilter(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  // first method called by spring ecosystem after setting username, password.
  //  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
    HttpServletResponse response) throws AuthenticationException {
    log.info("***** Stage 1: attemptAuthentication *****");
    // step 0: get username and password
    // if the username/pwd are taken from the url

    String username = obtainUsername(request);
    String password = obtainPassword(request);

    // step 1: create object by username and pwd
    // create a UsernamePasswordAuthenticationToken Object
    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
      username, password,null);

    /**
     *  step 2: call authenticate() method, va déclancher l'opération d'authentification,
     *  call UserDetailsService, loadUsers etc..
     */
    log.info("authenticationToken :{}", authenticationToken.getCredentials());
    Authentication authenticate = authenticationManager.authenticate(authenticationToken);
    return authenticate;
  }

  // if the check of password successfully passed, this will be the second method called by spring ecosystem.
//  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
    FilterChain chain, Authentication authResult) throws IOException, ServletException {
    log.info("**** Stage 2: successfulAuthentication ****");
    /**
     * getPrincipal(); permet de retourner l'utilisateur authentifier
     * ce User contient le username et les roles: le nécessaire pour générer un TOKEN
     * si a gestion du session été coté serveur, j'aurais pas besoin de faire tout ça
     */
    User user = (User) authResult.getPrincipal();

    /**
     * pour calculer la signature de JWT, utiliser un algorithme HMAC256 for eg
     */
    Algorithm algorithm = Algorithm.HMAC256(SecurityUtils.PRIVATE_SECRET);

    String jwtAccessToken = JWT.create()
      .withSubject(user.getUsername())
      .withExpiresAt(new Date(System.currentTimeMillis() + 1 * 60 * 1000))
      .withIssuer(request.getRequestURL().toString())  // issuer: le nom de l'application qui a générer le token = url de la request
      .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority)       // private claims
        .collect(Collectors.toList()))
      .sign(algorithm);      // last thing, set algorithm


    String refreshToken = JWT.create()
      .withSubject(user.getUsername())
      .withExpiresAt(new Date(System.currentTimeMillis() + 15 * 60 * 1000))
      .withIssuer(request.getRequestURL().toString())
      .sign(algorithm);

    Map<String, String> idToken = new HashMap<>();
    idToken.put("access-token", jwtAccessToken);
    idToken.put("refresh-token", refreshToken);
    response.setContentType("application/json");
    new ObjectMapper().writeValue(response.getOutputStream(), idToken);
    // set the jwt on response for example
    // response.addHeader("Authorization", jwtAccessToken);
    log.debug("Authorization Header : {}", response);
  }
}
