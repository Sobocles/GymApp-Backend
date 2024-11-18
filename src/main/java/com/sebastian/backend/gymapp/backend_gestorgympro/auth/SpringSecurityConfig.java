package com.sebastian.backend.gymapp.backend_gestorgympro.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

import com.sebastian.backend.gymapp.backend_gestorgympro.auth.filters.JwtAuthenticationFilter;
import com.sebastian.backend.gymapp.backend_gestorgympro.auth.filters.JwtValidatorFilter;

import java.util.Arrays;

@Configuration
@EnableMethodSecurity(prePostEnabled = true) // Permitir @PreAuthorize
public class SpringSecurityConfig {

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

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
        return http.authorizeHttpRequests()

                // Rutas públicas
                .requestMatchers("/login", "/public/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/carousel/images").permitAll()

                // Rutas de administración de usuarios
                .requestMatchers(HttpMethod.GET, "/users").permitAll()
                .requestMatchers(HttpMethod.GET, "/users/{id}").hasAnyRole("USER", "ADMIN")
                .requestMatchers(HttpMethod.PUT, "/users/profile").hasAnyRole("ADMIN", "TRAINER", "USER")
                .requestMatchers(HttpMethod.POST, "/users").hasRole("ADMIN")
                .requestMatchers("/users/**").hasRole("ADMIN")

                // Rutas relacionadas con planes (solo administradores)
                .requestMatchers(HttpMethod.GET, "/plans/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/plans/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/plans/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/plans/**").hasRole("ADMIN")

                // Rutas relacionadas con pagos
                .requestMatchers(HttpMethod.POST, "/payment/create_preference").authenticated()
                .requestMatchers(HttpMethod.POST, "/payment/webhook").permitAll() // Público para Mercado Pago

                // Rutas relacionadas con suscripciones (usuarios autenticados)
                .requestMatchers(HttpMethod.GET, "/subscriptions/**").authenticated()

                // Rutas del carrusel (administradores)
                .requestMatchers(HttpMethod.POST, "/carousel/images").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/carousel/images/**").hasRole("ADMIN")

                // Cualquier otra ruta
                .anyRequest().authenticated()

                // Configuración adicional
                .and()
                .addFilterBefore(new JwtValidatorFilter(authenticationConfiguration.getAuthenticationManager()),
                                 UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthenticationFilter(authenticationConfiguration.getAuthenticationManager()),
                                 UsernamePasswordAuthenticationFilter.class)
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("http://localhost:5173")); // Cambia según tu URL del frontend
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        config.setExposedHeaders(Arrays.asList("Authorization"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    FilterRegistrationBean<CorsFilter> corsFilter() {
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(corsConfigurationSource()));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
}
