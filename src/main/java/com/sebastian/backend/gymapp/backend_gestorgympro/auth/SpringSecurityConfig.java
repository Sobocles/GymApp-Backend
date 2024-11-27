package com.sebastian.backend.gymapp.backend_gestorgympro.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.sebastian.backend.gymapp.backend_gestorgympro.auth.filters.JwtAuthenticationFilter;
import com.sebastian.backend.gymapp.backend_gestorgympro.auth.filters.JwtValidatorFilter;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;

import java.util.Arrays;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SpringSecurityConfig {

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Autowired
    private UserRepository userRepository; // Inyectar el UserRepository

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authManager = authenticationManager();
    
        // Instanciar JwtAuthenticationFilter con las dependencias necesarias
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authManager, userRepository);
        jwtAuthenticationFilter.setFilterProcessesUrl("/login"); // Asegurar la URL de login
    
        // Instanciar JwtValidatorFilter sin argumentos
        JwtValidatorFilter jwtValidatorFilter = new JwtValidatorFilter();
    
        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/users", "/users/page/{page}").permitAll()
                        .requestMatchers(HttpMethod.GET, "/users/{id}").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/users/profile").hasAnyRole("ADMIN", "TRAINER", "USER")
                        .requestMatchers(HttpMethod.POST, "/users").hasRole("ADMIN")
                        .requestMatchers("/users/**").hasRole("ADMIN")
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/public/**").permitAll()
                        .requestMatchers("/payment/notifications").permitAll()
                        .requestMatchers("/payment/**").authenticated()
                        .requestMatchers(HttpMethod.GET, "/plans/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/plans/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/plans/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/plans/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/carousel/images").permitAll()
                        .requestMatchers(HttpMethod.POST, "/carousel/images").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/carousel/images/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                // Añadir JwtValidatorFilter antes de JwtAuthenticationFilter
                .addFilterBefore(jwtValidatorFilter, UsernamePasswordAuthenticationFilter.class)
                // Añadir JwtAuthenticationFilter en lugar de UsernamePasswordAuthenticationFilter
                .addFilterAt(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("http://localhost:5173")); // Asegúrate de incluir la URL correcta
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    FilterRegistrationBean<CorsFilter> corsFilter() {
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(
                new CorsFilter(corsConfigurationSource())
        );
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
}
