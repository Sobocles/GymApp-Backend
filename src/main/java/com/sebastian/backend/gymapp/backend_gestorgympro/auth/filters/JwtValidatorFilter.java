package com.sebastian.backend.gymapp.backend_gestorgympro.auth.filters;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sebastian.backend.gymapp.backend_gestorgympro.auth.SimpleGrantedAuthorityJsonCreator;
import com.sebastian.backend.gymapp.backend_gestorgympro.auth.TokenJwtConfig;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtValidatorFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    public JwtValidatorFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
    
        String header = request.getHeader(TokenJwtConfig.HEADER_AUTHORIZATION);
        System.err.println("AQUI ESTA EL HEADER"+header);
    
        if (header == null || !header.startsWith(TokenJwtConfig.PREFIX_TOKEN)) {
            chain.doFilter(request, response);
            return;
        }
    
        String token = header.replace(TokenJwtConfig.PREFIX_TOKEN, "");
        System.out.println("Token recibido: " + token);
    
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(TokenJwtConfig.SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
    
            String username = claims.getSubject();
            if (username == null) {
                throw new JwtException("No se encontró un nombre de usuario en el token.");
            }
    
            // Log para verificar los claims del token
            System.out.println("Claims obtenidos del token: " + claims);
    
            // Deserializar authorities como lista de mapas
            List<Map<String, String>> authoritiesList = (List<Map<String, String>>) claims.get("authorities");
            System.out.println("Authorities deserializados: " + authoritiesList);
    
            List<GrantedAuthority> authorities = authoritiesList.stream()
                    .map(authMap -> new SimpleGrantedAuthority(authMap.get("authority")))
                    .collect(Collectors.toList());
    
            System.out.println("Authorities convertidos: " + authorities);
    
            UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } catch (JwtException | ClassCastException e) {
            System.out.println("Error procesando el token JWT: " + e.getMessage());
    
            Map<String, String> body = new HashMap<>();
            body.put("error", e.getMessage());
            body.put("message", "El token JWT no es válido o tiene un formato inesperado en 'authorities'.");
            response.getWriter().write(new ObjectMapper().writeValueAsString(body));
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
        }
    }
    
    
    
    

    
    
}
