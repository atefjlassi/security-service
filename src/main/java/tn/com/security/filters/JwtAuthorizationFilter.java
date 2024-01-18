package tn.com.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import tn.com.security.utils.SecurityUtils;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

  /**
   * @param request
   * @param response
   * @param filterChain
   * @throws ServletException
   * @throws IOException      Cette methode s'éxecute a chaque fois ou il ya une requette. elle
   *                          l'intercept avant qu'elle atteint le dispatcher servlet
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
    FilterChain filterChain)
    throws ServletException, IOException {

    // s'il s'agit d'une requette de demande d'un nouveau access-token case(1)
    if (request.getServletPath().equals("/refreshToken")) {
      filterChain.doFilter(request, response);
    }
    // else, si la requette pour demande et vérifier si la requette est éligible ou non
    else {
      String authorizationToken = request.getHeader("Authorization");
      if (authorizationToken != null && authorizationToken.startsWith("Bearer ")) {
        try {
          // get the jwt
          String jwt = authorizationToken.substring(7).trim();
          // create an instance of the algorithm
          Algorithm algorithm = Algorithm.HMAC256(SecurityUtils.PRIVATE_SECRET);
          // create a verifier to verfier the token
          JWTVerifier jwtVerifier = JWT.require(algorithm).build();
          DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
          String username = decodedJWT.getSubject();
          String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

          List<SimpleGrantedAuthority> authorities = Arrays.stream(roles)
            .map(SimpleGrantedAuthority::new).collect(Collectors.toList());

          UsernamePasswordAuthenticationToken authenticatedUser =
            new UsernamePasswordAuthenticationToken(username, null, authorities);

          SecurityContextHolder.getContext().setAuthentication(authenticatedUser);

          // chain vers le filter suivant ou vers le dispatcher servlet
          filterChain.doFilter(request, response);

        } catch (Exception e) {
          response.setHeader("error-message", e.getMessage());
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }
      } else {
        filterChain.doFilter(request, response);
      }
    }
  }
}
