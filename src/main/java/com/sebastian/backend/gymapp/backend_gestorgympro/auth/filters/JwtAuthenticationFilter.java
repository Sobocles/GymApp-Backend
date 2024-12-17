package com.sebastian.backend.gymapp.backend_gestorgympro.auth.filters;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.Collection;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sebastian.backend.gymapp.backend_gestorgympro.auth.TokenJwtConfig;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository; // Dependencia inyectada

    

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        setFilterProcessesUrl("/login"); // Asegura que el filtro procese la URL de login
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        User user = null;
        String email = null;
        String password = null;
    
        try {
            user = new ObjectMapper().readValue(request.getInputStream(), User.class);
            email = user.getEmail();
            password = user.getPassword();
    
            System.out.println("Attempting authentication with email: " + email + " and password: " + password);
    
        } catch (IOException e) {
            e.printStackTrace();
        }
    
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(email, password);
        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        String email = ((org.springframework.security.core.userdetails.User) authResult.getPrincipal()).getUsername();
        Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();
    
        boolean isAdmin = roles.stream().anyMatch(r -> r.getAuthority().equals("ROLE_ADMIN"));
        boolean isTrainer = roles.stream().anyMatch(r -> r.getAuthority().equals("ROLE_TRAINER"));
    
        // Convertir las autoridades a una lista de cadenas
        List<String> authorities = roles.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    
        Claims claims = Jwts.claims();
        claims.put("authorities", authorities);
        claims.put("isAdmin", isAdmin);
        claims.put("isTrainer", isTrainer);
        claims.put("email", email);
    
        // Obtener el username real desde el repositorio
        Optional<User> userOpt = userRepository.findByEmail(email);
        String username = userOpt.map(User::getUsername).orElse("");
    
        claims.put("username", username);
    
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .signWith(TokenJwtConfig.SECRET_KEY, SignatureAlgorithm.HS256)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hora
                .compact();
    
        // Construir el cuerpo de respuesta JSON con isAuth
        Map<String, Object> body = new HashMap<>();
        body.put("isAuth", true);
        body.put("token", token);
        body.put("message", String.format("Hola %s, has iniciado sesión con éxito!", username));
        body.put("username", username);
        body.put("email", email);
        body.put("roles", authorities); // Enviar la lista de autoridades como List<String>
    
        // Log para verificar la estructura del cuerpo de respuesta
        System.out.println("Cuerpo de respuesta JSON: " + body);
    
        response.setContentType("application/json");
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {

        Map<String, Object> body = new HashMap<>();
        body.put("message", "Error en la autenticacion username o password incorrecto!");
        body.put("error", failed.getMessage());

        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(401);
        response.setContentType("application/json");
    }
}
