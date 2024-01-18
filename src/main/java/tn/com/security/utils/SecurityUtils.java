package tn.com.security.utils;

public class SecurityUtils {

  /**
   * la même signature utilisé pour signer le token, est la même pour vérifier le token (clé privé)
   * c'est le principe de HMAC.
   *
   * alors que pour RSA, pour signer on utilise private key, et pour vérifier on utilise un public key
   */
  public static final String PRIVATE_SECRET = "mySecret123";

}
