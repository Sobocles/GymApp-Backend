package com.sebastian.backend.gymapp.backend_gestorgympro.auth;

// TokenJwtConfig.java

import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

public class TokenJwtConfig {
    public static final String SECRET_KEY_STRING = "TuClaveSecretaDeAlMenos32CaracteresDeLongitud";
    public static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(SECRET_KEY_STRING.getBytes(StandardCharsets.UTF_8));
    public static final String PREFIX_TOKEN = "Bearer ";
    public static final String HEADER_AUTHORIZATION = "Authorization";
}



