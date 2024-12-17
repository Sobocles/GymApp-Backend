package com.sebastian.backend.gymapp.backend_gestorgympro.auth.filters;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sebastian.backend.gymapp.backend_gestorgympro.auth.TokenJwtConfig;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtValidatorFilter extends OncePerRequestFilter {

    // Constructor sin parámetros
    public JwtValidatorFilter() {
    }


   
    

    


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

                
             
        System.out.println("=== Headers recibidos en la solicitud ===");
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            System.out.println(headerName + ": " + request.getHeader(headerName));
        }
        System.out.println("=======================================");       
    
        String header = request.getHeader(TokenJwtConfig.HEADER_AUTHORIZATION);
        System.out.println("JwtValidatorFilter - Header Authorization: " + header);
    
        if (header == null || !header.startsWith(TokenJwtConfig.PREFIX_TOKEN)) {
            chain.doFilter(request, response);
            return;
        }
    
        String token = header.replace(TokenJwtConfig.PREFIX_TOKEN, "");
        System.out.println("JwtValidatorFilter - Token recibido: " + token);
    
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(TokenJwtConfig.SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
    
            System.out.println("Claims obtenidos del token: " + claims);
    
            String username = claims.getSubject();
            if (username == null) {
                throw new JwtException("No se encontró un nombre de usuario en el token.");
            }
    
            System.out.println("JwtValidatorFilter - Email extraído: " + username);
    
            // Verificar el tipo del claim "authorities"
            Object authoritiesObj = claims.get("authorities");
            if (authoritiesObj == null) {
                throw new JwtException("'authorities' claim is missing");
            }
            System.out.println("Tipo del claim 'authorities': " + authoritiesObj.getClass());
    
            if (!(authoritiesObj instanceof List<?>)) {
                throw new JwtException("'authorities' claim no es una lista");
            }
    
            List<?> rawList = (List<?>) authoritiesObj;
            System.out.println("Contenido de 'authorities': " + rawList);
            for (Object obj : rawList) {
                System.out.println("Elemento en 'authorities': " + obj + ", tipo: " + obj.getClass());
            }
    
            // Usar ObjectMapper con TypeReference
            ObjectMapper mapper = new ObjectMapper();
            List<String> authoritiesList = mapper.convertValue(authoritiesObj, new TypeReference<List<String>>() {});
    
            System.out.println("JwtValidatorFilter - Authorities List deserializado: " + authoritiesList );
    
            // Verificar que todas las autoridades sean cadenas
            for (Object authority : authoritiesList) {
                if (!(authority instanceof String)) {
                    throw new JwtException("Authority is not a string: " + authority);
                }
            }
    
            List<GrantedAuthority> authorities = authoritiesList.stream()
                    .map(SimpleGrantedAuthority::new)
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
            body.put("message", "El token JWT no es válido o ha expirado.");
            response.getWriter().write(new ObjectMapper().writeValueAsString(body));
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
        }
    }
    
}
