package com.sebastian.backend.gymapp.backend_gestorgympro;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BackendGestorgymproApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendGestorgymproApplication.class, args);
	}

}
package com.sebastian.backend.gymapp.backend_gestorgympro.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAuthorityJsonCreator {

    @JsonCreator
    public SimpleGrantedAuthorityJsonCreator(@JsonProperty("authority") String role ){

    }
}
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
                .requestMatchers(HttpMethod.POST, "/group-classes/create").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/payment/notifications").permitAll()

                .requestMatchers(HttpMethod.POST, "users/register").permitAll()
                
                        // Rutas públicas
                        .requestMatchers(HttpMethod.GET, "/users", "/users/page/{page}").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/public/**").permitAll()
                        

                        .requestMatchers(HttpMethod.GET, "/plans/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/carousel/images").permitAll()
                      
    
                        // Rutas accesibles para ADMIN
                        .requestMatchers(HttpMethod.GET, "/users/dashboard").hasRole("USER")
                        .requestMatchers(HttpMethod.POST, "/users").hasRole("ADMIN")
                                      // **Matcher específico para /users/personal-trainer**
                        .requestMatchers("/users/personal-trainer").hasRole("USER")
                        .requestMatchers("/users/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/plans/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/plans/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/plans/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/carousel/images").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/carousel/images/**").hasRole("ADMIN")
                 
                        // Rutas accesibles para TRAINER y ADMIN
                            // Rutas accesibles para TRAINER y ADMIN
                        .requestMatchers(HttpMethod.GET, "/trainers/available").permitAll()
                        .requestMatchers("/trainers/**").hasAnyRole("TRAINER", "ADMIN")

                        // Suponiendo que quieres que los usuarios autenticados vean categorías
                        .requestMatchers(HttpMethod.GET, "/store/categories").permitAll()
                        .requestMatchers(HttpMethod.POST, "/store/categories").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/store/categories/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/store/categories/**").hasRole("ADMIN")



                        .requestMatchers(HttpMethod.GET, "/store/products/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/store/products").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/store/products/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/store/products/**").hasRole("ADMIN")


                       
    
                        // Rutas accesibles para USER, TRAINER y ADMIN
                        .requestMatchers("/clients/**").hasAnyRole("USER", "TRAINER", "ADMIN")
    
                        // Rutas de pago accesibles para usuarios autenticados
                        .requestMatchers("/payment/**").authenticated()

                            // Rutas de Trainer Schedule accesibles para TRAINER y ADMIN
                            .requestMatchers("/trainer-schedule/**").hasAnyRole("TRAINER", "ADMIN", "USER")

                                 // Aquí agregas las rutas de las clases grupales
                       
                        .requestMatchers(HttpMethod.POST, "/group-classes/{classId}/assign-trainer").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/group-classes/available").hasAnyRole("USER", "TRAINER", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/group-classes/{classId}/book").hasAnyRole("USER", "TRAINER", "ADMIN")
    
                        // Otras rutas requerirán autenticación
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
        config.setAllowedOriginPatterns(Arrays.asList("*")); // Cambiar a setAllowedOriginPatterns
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
        Long userId = userOpt.map(User::getId).orElse(null);
        String username = userOpt.map(User::getUsername).orElse("");
        
        claims.put("id", userId); // Agregar el ID del usuario
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

//AQUIIIIIIIIIIIIIIIIIIIIIIIIIIIII-----------------------
package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.services.CloudinaryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.CarouselImage;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.CarouselImageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/carousel")
public class CarouselController {

    @Autowired
    private CloudinaryService cloudinaryService;

    @Autowired
    private CarouselImageRepository carouselImageRepository;

    // Otros métodos...

    @PostMapping("/images")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<CarouselImage> addCarouselImage(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "caption", required = false) String caption,
            @RequestParam(value = "order", required = false, defaultValue = "0") Integer orderNumber
    ) {
        try {
            // Sube la imagen a Cloudinary
            String imageUrl = cloudinaryService.uploadImage(file);
    
            // Crear y guardar la entidad CarouselImage
            CarouselImage carouselImage = new CarouselImage();
            carouselImage.setImageUrl(imageUrl);
            carouselImage.setCaption(caption);
            carouselImage.setOrderNumber(orderNumber);
    
            CarouselImage savedImage = carouselImageRepository.save(carouselImage);
    
            return ResponseEntity.ok(savedImage);
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).build();
        }
    }

    // Obtener detalles de una imagen (opcional)
    @GetMapping("/images/{publicId}")
    public ResponseEntity<Map<String, Object>> getImageDetails(@PathVariable String publicId) {
        try {
            Map details = cloudinaryService.getImageDetails(publicId);
            return ResponseEntity.ok(details);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).build();
        }
    }

    // Obtener la URL de una imagen transformada (opcional)
    @GetMapping("/images/{publicId}/transformed")
    public ResponseEntity<String> getTransformedImageUrl(@PathVariable String publicId) {
        String url = cloudinaryService.getTransformedImageUrl(publicId);
        return ResponseEntity.ok(url);
    }

    // Obtener todas las imágenes del carrusel
    @GetMapping("/images")
    public ResponseEntity<List<CarouselImage>> getAllCarouselImages() {
        List<CarouselImage> images = carouselImageRepository.findAllByOrderByOrderNumberAsc();
        return ResponseEntity.ok(images);
    }

}
package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/store/categories")
public class CategoryController {

    @Autowired
    private CategoryService categoryService;

    // Crear una nueva categoría (solo ADMIN)
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Category> createCategory(@RequestParam String name) {
        Category category = categoryService.createCategory(name);
        return ResponseEntity.ok(category);
    }

 
    @GetMapping
    public ResponseEntity<List<Category>> getAllCategories() {
        return ResponseEntity.ok(categoryService.getAllCategories());
    }

    // Actualizar categoría (solo ADMIN)
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Category> updateCategory(@PathVariable Long id, @RequestParam String newName) {
        Category updated = categoryService.updateCategory(id, newName);
        return ResponseEntity.ok(updated);
    }

    // Eliminar categoría (solo ADMIN)
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteCategory(@PathVariable Long id) {
        categoryService.deleteCategory(id);
        return ResponseEntity.noContent().build();
    }
}

package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Booking;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Routine;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerScheduleService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Booking;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import java.util.Collections;


@RestController
@RequestMapping("/clients")
public class ClientController {

    @Autowired
    private TrainerService trainerService;

    @Autowired
    private UserService userService;

    @Autowired
    private TrainerScheduleService trainerScheduleService;
    

    @GetMapping("/{clientId}/measurements")
    @PreAuthorize("hasAnyRole('USER', 'TRAINER', 'ADMIN')")
    public ResponseEntity<List<BodyMeasurement>> getBodyMeasurements(@PathVariable Long clientId) {
        List<BodyMeasurement> measurements = trainerService.getClientBodyMeasurements(clientId);
        return ResponseEntity.ok(measurements);
    }

    @GetMapping("/{clientId}/routines")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<Routine>> getRoutines(@PathVariable Long clientId) {
        List<Routine> routines = trainerService.getClientRoutines(clientId);
        return ResponseEntity.ok(routines);
    }

    @GetMapping("/{clientId}/sessions")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<CalendarEventDTO>> getClientSessions(
            @PathVariable Long clientId,
            Authentication authentication) {
    
        String email = authentication.getName();
        Optional<User> userOpt = userService.findByEmail(email);
        
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    
        User user = userOpt.get();
    
        if (!user.getId().equals(clientId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body(Collections.emptyList());
        }
    
        List<CalendarEventDTO> events = trainerScheduleService.getClientSessions(clientId);
    
        return ResponseEntity.ok(events);
    }
    

}

package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.GroupClassDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.CreateGroupClassRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.GroupClassBookingService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.GroupClassService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/group-classes")
public class GroupClassController {

    @Autowired
    private GroupClassService groupClassService;

    @Autowired
    private GroupClassBookingService groupClassBookingService;

    @Autowired
    private UserService userService;

    /**
     * Crear una nueva clase grupal (solo ADMIN)
     */
    @PostMapping("/create")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createClass(@RequestBody CreateGroupClassRequest request) {
        GroupClass gc = groupClassService.createGroupClass(
            request.getClassName(), 
            request.getStartTime(), 
            request.getEndTime(), 
            request.getMaxParticipants()
        );
    
        // Si se proporciona un trainerId, asignarlo
        if (request.getTrainerId() != null) {
            try {
                groupClassService.assignTrainerToClass(gc.getId(), request.getTrainerId());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
            }
        }
    
        return ResponseEntity.status(HttpStatus.CREATED).body(gc);
    }
    

    /**
     * Asignar un entrenador a la clase grupal (solo ADMIN)
     */
    @PostMapping("/{classId}/assign-trainer")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> assignTrainer(@PathVariable Long classId, @RequestParam Long trainerId) {
        groupClassService.assignTrainerToClass(classId, trainerId);
        return ResponseEntity.ok("Entrenador asignado a la clase");
    }

    /**
     * Listar clases disponibles para el usuario
     * Aquí filtramos solo las clases visibles: que no hayan empezado, que estén en el rango de reserva, y que no estén llenas.
     */
    @GetMapping("/available")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'TRAINER')")
    public ResponseEntity<?> listAvailableClasses() {
        List<GroupClassDto> futureClasses = groupClassService.findFutureClasses(); 
        return ResponseEntity.ok(futureClasses);
    }
    

    /**
     * Reservar una clase grupal (USER con plan o USER con trainer)
     */
    @PostMapping("/{classId}/book")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'TRAINER')")
    public ResponseEntity<?> bookClass(@PathVariable Long classId, Authentication auth) {
        String email = auth.getName();
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autenticado");
        }
        User user = userOpt.get();

        try {
            groupClassBookingService.bookClass(user, classId);
            return ResponseEntity.ok("Clase reservada con éxito");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }


    @GetMapping("/{classId}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'TRAINER')")
    public ResponseEntity<GroupClassDto> getClassDetails(@PathVariable Long classId) {
        GroupClassDto classDetails = groupClassService.getClassDetails(classId);
        return ResponseEntity.ok(classDetails);
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;


import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;

import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;

import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentNotificationService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentReportService;

import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanTrainerPaymentService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProductPaymentService;


import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;



@RestController
@RequestMapping("/payment")
public class PaymentController {

 

    @Autowired
    private PaymentReportService paymentReportService;

    @Autowired
    private PlanTrainerPaymentService planTrainerPaymentService;

    @Autowired
    private PaymentNotificationService paymentNotificationService;

        @Autowired
    private ProductPaymentService productPaymentService;



    @Value("${mercadopago.successUrl}")
    private String successUrl;

    @Value("${mercadopago.failureUrl}")
    private String failureUrl;

    @Value("${mercadopago.pendingUrl}")
    private String pendingUrl;
    
    @PostMapping("/create_plan_preference")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Preference createPlanPaymentPreference(
            @RequestParam(required = false) Long planId,
            @RequestParam(required = false) Long trainerId,
            @RequestParam(required = false, defaultValue = "false") boolean onlyTrainer
    ) throws MPException {
        // 1. Obtener el email del usuario autenticado
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();

        // 2. Delegar toda la lógica al servicio
        return planTrainerPaymentService.createPlanTrainerPayment(userEmail, planId, trainerId, onlyTrainer);
    }
    

    @PostMapping("/create_product_preference")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Preference createProductPaymentPreference(
            @RequestBody List<Map<String, Object>> items,
            Authentication authentication) throws MPException {

        String userEmail = authentication.getName();
        return productPaymentService.createProductPayment(userEmail, items);
    }
    
    
    @PostMapping("/notifications")
    public ResponseEntity<String> receiveNotification(@RequestParam Map<String, String> params) {
        try {
            paymentNotificationService.processNotification(params);
            return ResponseEntity.ok("Received");
        } catch (MPException | MPApiException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Error al procesar la notificación");
        }
    }
    
    
    @GetMapping("/my-payments")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<PaymentDTO>> getMyPayments(Authentication authentication) {
        try {
            List<PaymentDTO> payments = paymentReportService.getMyPayments(authentication.getName());
            return ResponseEntity.ok(payments);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/total-revenue")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, BigDecimal>> getTotalRevenue() {
        try {
            BigDecimal totalRevenue = paymentReportService.getTotalRevenue();
            return ResponseEntity.ok(Map.of("totalRevenue", totalRevenue));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", BigDecimal.ZERO));
        }
    }
/* 
    @GetMapping("/revenue-by-service-type/{serviceType}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, BigDecimal>> getRevenueByServiceType(@PathVariable String serviceType) {
        try {
            // Convertir el parámetro de ruta a ServiceType enum
            Payment.serviceType type = Payment.serviceType.valueOf(serviceType.toUpperCase());

            BigDecimal totalRevenue = paymentService.getTotalRevenueByServiceType(type);
            return ResponseEntity.ok(Map.of(
                "serviceType", new BigDecimal(type.ordinal()), // Para incluir el tipo de servicio en la respuesta
                "totalRevenue", totalRevenue
            ));
        } catch (IllegalArgumentException e) {
            // Maneja el caso en que el serviceType proporcionado no es válido
            return ResponseEntity.badRequest().body(Map.of("error", BigDecimal.ZERO));
        } catch (Exception e) {
            System.err.println("Error al obtener la suma total de ingresos por tipo de servicio: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", BigDecimal.ZERO));
        }
    }
*/
        @GetMapping("/admin-dashboard-revenue")
        @PreAuthorize("hasRole('ADMIN')")
        public ResponseEntity<Map<String, Object>> getAdminDashboardRevenue() {
            try {
                Map<String, Object> revenue = paymentReportService.getAdminDashboardRevenue();
                return ResponseEntity.ok(revenue);
            } catch (Exception e) {
                return ResponseEntity.status(500).body(Map.of("error", "Error interno del servidor"));
            }
        }



    
    

}
package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/plans")
public class PlanController {

    @Autowired
    private PlanService planService;

    @GetMapping
    public List<Plan> getAllPlans() {
        return planService.getAllPlans();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Plan> getPlanById(@PathVariable Long id) {
        Plan plan = planService.getPlanById(id);
        if (plan != null) {
            return ResponseEntity.ok(plan);
        }
        return ResponseEntity.notFound().build();
    }

    @PostMapping
    public Plan createPlan(@RequestBody Plan plan) {
        return planService.createPlan(plan);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Plan> updatePlan(@PathVariable Long id, @RequestBody Plan planDetails) {
        Plan updatedPlan = planService.updatePlan(id, planDetails);
        if (updatedPlan != null) {
            return ResponseEntity.ok(updatedPlan);
        }
        return ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePlan(@PathVariable Long id) {
        planService.deletePlan(id);
        return ResponseEntity.noContent().build();
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ProductDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import com.sebastian.backend.gymapp.backend_gestorgympro.services.CloudinaryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProductService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CategoryService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile; 
import org.springframework.http.MediaType;


import java.io.IOException;
import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/store")
public class ProductController {
    
    @Autowired
    private ProductService productService;
    
    @Autowired
    private CloudinaryService cloudinaryService;

    @Autowired
    private CategoryService categoryService;
/*
 @PostMapping(value = "/products", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
@PreAuthorize("hasAnyRole('ADMIN')")
public ResponseEntity<ProductDto> createProduct(
        @RequestParam("name") String name,
        @RequestParam("description") String description,
        @RequestParam("category") String category,
        @RequestParam("price") Double price,
        @RequestPart(value = "image", required = false) MultipartFile image
) {
    String imageUrl = null;
    if (image != null && !image.isEmpty()) {
        try {
            imageUrl = cloudinaryService.uploadImage(image);
        } catch (IOException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    // Obtener la categoría por nombre
    Category categoryEntity = categoryService.getCategoryByName(category);
    if (categoryEntity == null) {
        return ResponseEntity.badRequest().body(null); // Manejar categoría no encontrada
    }

    // Crear el producto
    Product product = new Product();
    product.setName(name);
    product.setDescription(description);
    product.setCategory(categoryEntity);
    product.setPrice(BigDecimal.valueOf(price));
    product.setImageUrl(imageUrl);

    Product createdProduct = productService.createProduct(product);

    // Convertir a DTO
    ProductDto productDto = new ProductDto();
    productDto.setName(createdProduct.getName());
    productDto.setDescription(createdProduct.getDescription());
    productDto.setCategory(createdProduct.getCategory().getName());
    productDto.setPrice(createdProduct.getPrice().doubleValue());

    return ResponseEntity.ok(productDto);
}

 */
    @PostMapping(value = "/products", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Product> createProduct(
        @RequestParam("name") String name,
        @RequestParam("description") String description,
        @RequestParam("category") String category,
        @RequestParam("price") Double price,
        @RequestPart(value = "image", required = false) MultipartFile image
    ) {
        String imageUrl = null;
        if (image != null && !image.isEmpty()) {
            try {
                imageUrl = cloudinaryService.uploadImage(image);
            } catch (IOException e) {
                return ResponseEntity.badRequest().build();
            }
        }
    
        // Obtener la categoría por nombre
        Category categoryEntity = categoryService.getCategoryByName(category);
        if (categoryEntity == null) {
            return ResponseEntity.badRequest().body(null); // Manejar categoría no encontrada
        }
    
        // Crear el producto
        Product product = new Product();
        product.setName(name);
        product.setDescription(description);
        product.setCategory(categoryEntity);
        product.setPrice(BigDecimal.valueOf(price));
        product.setImageUrl(imageUrl);
    
        Product createdProduct = productService.createProduct(product);
        return ResponseEntity.ok(createdProduct);
    }
    

    @GetMapping("/products")
    public ResponseEntity<List<Product>> getAllProducts(@RequestParam(required = false) String category) {
        if (category != null && !category.isEmpty()) {
            // Filtrar por categoría
            Category categoryEntity = categoryService.getCategoryByName(category);
            List<Product> productsByCategory = productService.getProductsByCategory(categoryEntity);
            return ResponseEntity.ok(productsByCategory);
        } else {
            // Sin filtro de categoría
            return ResponseEntity.ok(productService.getAllProducts());
        }
    }

    
    @GetMapping("/products/{id}")
    public ResponseEntity<Product> getProductById(@PathVariable Long id) {
        return ResponseEntity.ok(productService.getProductById(id));
    }

    
    @PutMapping("/products/{id}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Product> updateProduct(@PathVariable Long id,
                                                 @RequestParam(required = false) String name,
                                                 @RequestParam(required = false) String description,
                                                 @RequestParam(required = false) String category,
                                                 @RequestParam(required = false) Double price,
                                                 @RequestParam(required = false) MultipartFile image) {
        Product productDetails = productService.getProductById(id);

        if (name != null) productDetails.setName(name);
        if (description != null) productDetails.setDescription(description);
        
        if (category != null) {
            Category categoryEntity = categoryService.getCategoryByName(category);
            productDetails.setCategory(categoryEntity);
        }

        if (price != null) productDetails.setPrice(BigDecimal.valueOf(price));

        if (image != null && !image.isEmpty()) {
            try {
                String imageUrl = cloudinaryService.uploadImage(image);
                productDetails.setImageUrl(imageUrl);
            } catch (IOException e) {
                return ResponseEntity.badRequest().build();
            }
        }

        Product updatedProduct = productService.updateProduct(id, productDetails);
        return ResponseEntity.ok(updatedProduct);
    }

    @DeleteMapping("/products/{id}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Void> deleteProduct(@PathVariable Long id) {
        productService.deleteProduct(id);
        return ResponseEntity.noContent().build();
    }


  
@GetMapping("/products/page/{page}")
public ResponseEntity<Page<Product>> getProductsPage(
    @PathVariable int page,
    @RequestParam(defaultValue = "12") int size,
    @RequestParam(required = false) String category
) {
    Pageable pageable = PageRequest.of(page, size);
    Page<Product> productPage;

    if (category != null && !category.isEmpty()) {
        Category cat = categoryService.getCategoryByName(category);
        productPage = productService.findByCategory(cat, pageable);
    } else {
        productPage = productService.findAll(pageable);
    }

    return ResponseEntity.ok(productPage);
}

// ProductController.java
@GetMapping("/products/search")
public ResponseEntity<List<Product>> searchProducts(@RequestParam("term") String term) {
    // Por simplicidad, filtramos solo por nombre. Ajusta según tu lógica.
    List<Product> results = productService.searchProducts(term);
    return ResponseEntity.ok(results);
}


}
package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProfileService;

@RestController
@RequestMapping("/profile")
public class ProfileController {

        @Autowired
        private ProfileService profileService;

    @PutMapping("/update")
    @PreAuthorize("hasAnyRole('ADMIN','TRAINER','USER')")
    public ResponseEntity<?> updateProfile(
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "email", required = false) String email,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "file", required = false) MultipartFile file) {
        try {
            UserRequest userRequest = new UserRequest();
            userRequest.setUsername(username);
            userRequest.setEmail(email);
            userRequest.setPassword(password);

            // Obtener el email actual del usuario autenticado
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String currentEmail = authentication.getName();

            UserDto updatedUser = profileService.updateProfile(userRequest, file, currentEmail);
            return ResponseEntity.ok(updatedUser);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al actualizar el perfil");
        }
    }

}
// src/main/java/com/sebastian/backend/gymapp/backend_gestorgympro/controllers/PublicController.java

package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class PublicController {

    @GetMapping("/info")
    public ResponseEntity<?> getPublicInfo() {
        // Retorna la información pública necesaria
        return ResponseEntity.ok("Información pública del gimnasio");
    }
    

}
package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ActiveClientInfoDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.BodyMeasurementDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerAssignmentRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerUpdateRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear.DtoMapperUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Routine;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerClient;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerClientRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.SubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;

import org.springframework.transaction.annotation.Transactional;


@RestController
@RequestMapping("/trainers")
public class TrainerController {

    @Autowired
    private UserService userService;

    @Autowired
    private TrainerService trainerService;

    @Autowired
private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Autowired
    private SubscriptionService subscriptionService;

        @Autowired
    private TrainerClientRepository trainerClientRepository;


// TrainerController.java

@PostMapping("/{id}/assign")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> assignTrainerRole(@PathVariable Long id, @RequestBody TrainerAssignmentRequest request) {
    System.out.println("=== Datos recibidos para asignar entrenador ===");
    System.out.println("ID del usuario: " + id);
    System.out.println("Especialización: " + request.getSpecialization());
    System.out.println("Años de experiencia: " + request.getExperienceYears());
    System.out.println("Disponibilidad: " + request.getAvailability());
    System.out.println("Cuota mensual: " + request.getMonthlyFee());
    System.out.println("Título: " + request.getTitle());
    System.out.println("Estudios: " + request.getStudies());
    System.out.println("Certificaciones: " + request.getCertifications());
    System.out.println("Descripción: " + request.getDescription());
    
    trainerService.assignTrainerRole(
        id,
        request.getSpecialization(),
        request.getExperienceYears(),
        request.getAvailability(),
        request.getMonthlyFee(),
        request.getTitle(),          
        request.getStudies(),
        request.getCertifications(),
        request.getDescription()
    );
    return ResponseEntity.ok("Rol de Trainer asignado correctamente y especialización añadida");
}


    

@PostMapping("/clients/{clientId}/measurements")
@PreAuthorize("hasRole('TRAINER')")
public ResponseEntity<?> addBodyMeasurement(
        @PathVariable Long clientId,
        @RequestBody BodyMeasurementDto measurementDto,
        Authentication authentication) {

    String email = authentication.getName();
    Optional<User> trainerOpt = userService.findByEmail(email);
    if (trainerOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    User trainer = trainerOpt.get();
    trainerService.addBodyMeasurement(trainer.getId(), clientId, measurementDto);
    return ResponseEntity.ok("Medición corporal añadida exitosamente");
}

    

    @PostMapping("/clients/{clientId}/routines")
    @PreAuthorize("hasRole('TRAINER')")
    public ResponseEntity<?> addRoutine(
            @PathVariable Long clientId,
            @RequestBody Routine routine,
            Authentication authentication) {
    
        String email = authentication.getName();
        Optional<User> trainerOpt = userService.findByEmail(email);
        if (!trainerOpt.isPresent()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        User trainer = trainerOpt.get();
    
        trainerService.addRoutine(trainer.getId(), clientId, routine);
        return ResponseEntity.ok("Rutina añadida exitosamente");
    }

    @PostMapping("/clients/{clientId}")
    @PreAuthorize("hasRole('TRAINER')")
    public ResponseEntity<?> addClientToTrainer(
            @PathVariable Long clientId,
            Authentication authentication) {

        String email = authentication.getName();
        Optional<User> trainerOpt = userService.findByEmail(email);
        if (!trainerOpt.isPresent()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        User trainer = trainerOpt.get();

        trainerService.addClientToTrainer(trainer.getId(), clientId);
        return ResponseEntity.ok("Cliente asignado al entrenador exitosamente");
    }
    
/* 
        @GetMapping("/clients")
    @PreAuthorize("hasRole('TRAINER')")
    public ResponseEntity<List<UserDto>> getAssignedClients(Authentication authentication) {
        String email = authentication.getName();
        Optional<User> trainerOpt = userService.findByEmail(email);
        if (trainerOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        User trainer = trainerOpt.get();
        List<UserDto> clients = trainerService.getAssignedClients(trainer.getId());
        return ResponseEntity.ok(clients);
    }
    */
@GetMapping("/clients")
@PreAuthorize("hasRole('TRAINER')")
public ResponseEntity<List<UserDto>> getAssignedClients(Authentication authentication) {
    String email = authentication.getName();
    Optional<User> trainerOpt = userService.findByEmail(email);
    if (trainerOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    User trainer = trainerOpt.get();
    
    // Obtener el PersonalTrainer asociado al User
    Optional<PersonalTrainer> personalTrainerOpt = trainerService.findByUserId(trainer.getId());
    if (personalTrainerOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
    }
    PersonalTrainer personalTrainer = personalTrainerOpt.get();
    
    // Ahora usa el ID de PersonalTrainer
    List<UserDto> clients = trainerService.getAssignedClients(personalTrainer.getId());
    return ResponseEntity.ok(clients);
}




    @PutMapping("/update_details")
@PreAuthorize("hasRole('TRAINER')")
public ResponseEntity<?> updateTrainerDetails(@RequestBody TrainerUpdateRequest request, Authentication authentication) {
    String email = authentication.getName();
    trainerService.updateTrainerDetails(email, request);
    return ResponseEntity.ok("Datos del entrenador actualizados con éxito");
}

        @GetMapping("/active-clients-info")
        @PreAuthorize("hasRole('TRAINER')")
        public ResponseEntity<List<ActiveClientInfoDTO>> getActiveClientsInfo(Authentication authentication) {
            // 1. Encontrar al User entrenador
            String email = authentication.getName();
            Optional<User> trainerUserOpt = userService.findByEmail(email);
            if (trainerUserOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            User trainerUser = trainerUserOpt.get();

            // 2. Encontrar su PersonalTrainer
            Optional<PersonalTrainer> ptOpt = trainerService.findByUserId(trainerUser.getId());

            if (ptOpt.isEmpty()) {
                // Si no está registrado como trainer
                return ResponseEntity.badRequest().body(Collections.emptyList());
            }
            Long personalTrainerId = ptOpt.get().getId();

            // 3. Delegar toda la lógica al servicio
            List<ActiveClientInfoDTO> infoList = trainerService.getActiveClientsInfoForTrainer(personalTrainerId);

            return ResponseEntity.ok(infoList);
        }

        @GetMapping("/findByUserId/{userId}")
    @PreAuthorize("hasRole('TRAINER')") 
    // ^ OJO: Ajusta según quieras quién puede consultar.
    public ResponseEntity<Map<String, Object>> getTrainerByUserId(@PathVariable Long userId) {
        return trainerService.findByUserId(userId)
            .map(pt -> {
                // Devolvemos un JSON con { id: xx, ... } o lo que necesites
                Map<String, Object> response = new HashMap<>();
                response.put("id", pt.getId()); 
                response.put("username", pt.getUser().getUsername());
                response.put("specialization", pt.getSpecialization());
                return ResponseEntity.ok(response);
            })
            .orElseGet(() -> ResponseEntity.notFound().build());
    }
        
}
package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TimeSlotDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerAvailabilityRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerAvailability;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerAvailabilityRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.GroupClassService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerScheduleService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.impl.SubscriptionServiceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/trainer-schedule")
public class TrainerScheduleController {



    @Autowired
    private UserService userService;

    @Autowired
    private SubscriptionServiceImpl subscriptionService;

    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Autowired
    private TrainerAvailabilityRepository trainerAvailabilityRepository;

    @Autowired
    private TrainerService trainerService;

    @Autowired
    private TrainerScheduleService trainerScheduleService;

    @Autowired
    private GroupClassService groupClassService;

    @Autowired
    private BookingRepository bookingRepository; 


    @GetMapping("/{trainerId}/weekly-slots")
    @PreAuthorize("hasAnyRole('USER', 'TRAINER', 'ADMIN')")
    public ResponseEntity<?> getWeeklySlots(@PathVariable Long trainerId, Authentication authentication) {
        String email = authentication.getName();
        System.out.println("Usuario autenticado: " + email);
    
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            System.out.println("Usuario no autenticado.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body("Usuario no autenticado");
        }
    
        User user = userOpt.get();
        System.out.println("Usuario encontrado: " + user.getId() + " - " + user.getEmail());
    
        boolean hasSubscription = subscriptionService.hasActivePlanWithTrainer(user.getId(), trainerId) ||
                                   personalTrainerSubscriptionService.hasActiveTrainerSubscription(user.getId(), trainerId);
        System.out.println("El usuario tiene suscripción activa con el entrenador: " + hasSubscription);
    
        if (!hasSubscription) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body("No tienes una suscripción activa para ver los slots semanales de este entrenador.");
        }
    
        List<TimeSlotDTO> slots = trainerScheduleService.getWeeklySlotsForTrainer(trainerId);
        System.out.println("Slots generados para el entrenador " + trainerId + ": " + slots);
    
        return ResponseEntity.ok(slots);
    }
    
    @PostMapping("/book")
    @PreAuthorize("hasAnyRole('USER', 'TRAINER', 'ADMIN')")
    public ResponseEntity<?> bookSlot(@RequestParam Long trainerId,
                                      @RequestParam String slotStart,
                                      Authentication authentication) {
        String currentUserEmail = authentication.getName();
    
        Optional<User> userOpt = userService.findByEmail(currentUserEmail);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autenticado");
        }
    
        User user = userOpt.get();
    
        try {
            LocalDateTime slotDateTime = LocalDateTime.parse(slotStart);
            boolean success = trainerScheduleService.bookSlot(user.getId(), trainerId, slotDateTime);
    
            if (success) {
                return ResponseEntity.ok("Reserva exitosa");
            } else {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("El horario ya ha sido reservado.");
            }
    
        } catch (IllegalStateException e) {
            System.out.println("Reserva fallida: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                        "error", "Reserva no permitida",
                        "message", e.getMessage()  // Envía el mensaje exacto
                    ));
        } catch (DateTimeParseException e) {
            return ResponseEntity.badRequest().body("Formato de fecha y hora inválido");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                        "error", "Error inesperado",
                        "message", "Ocurrió un error al procesar la reserva"
                    ));
        }
    }
    
    @PostMapping("/{trainerId}/availability")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createTrainerAvailability(@PathVariable Long trainerId,
                                                       @RequestBody TrainerAvailabilityRequest request) {
        PersonalTrainer trainer = trainerService.findPersonalTrainerById(trainerId)
                .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));
    
        TrainerAvailability availability = new TrainerAvailability();
        availability.setTrainer(trainer);
        availability.setDay(request.getDay());
        availability.setStartTime(request.getStartTime());
        availability.setEndTime(request.getEndTime());

        trainerAvailabilityRepository.save(availability);

        return ResponseEntity.status(HttpStatus.CREATED).body("Disponibilidad creada exitosamente");
    }

    @GetMapping("/{trainerId}/calendar")
    public ResponseEntity<?> getTrainerCalendar(@PathVariable Long trainerId, Authentication authentication) {
        List<CalendarEventDTO> events = trainerScheduleService.getTrainerCalendar(trainerId);
        return ResponseEntity.ok(events);
    }



            // Nuevo endpoint para obtener entrenadores disponibles
            @GetMapping("/all-available")
            @PreAuthorize("hasAnyRole('USER', 'TRAINER', 'ADMIN')")
            public ResponseEntity<List<PersonalTrainerDto>> getAllAvailableTrainers() {
                // Llamada al servicio que obtiene todos los entrenadores disponibles
                List<PersonalTrainerDto> availableTrainers = trainerService.getAvailableTrainers();
                return ResponseEntity.ok(availableTrainers);
            }

    @PostMapping("/{classId}/assign-trainer")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> assignTrainerToClass(@PathVariable Long classId,
                                                @RequestParam Long trainerId) {
        GroupClass groupClass = groupClassService.findById(classId)
                .orElseThrow(() -> new IllegalArgumentException("Clase no encontrada con ID: " + classId));

        PersonalTrainer trainer = trainerService.findPersonalTrainerById(trainerId)
                .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));

        // Validar disponibilidad del entrenador para ese horario
        boolean hasOverlap = bookingRepository.hasOverlappingBookings(trainerId, groupClass.getStartTime(), groupClass.getEndTime());
        boolean isAvailableForClass = trainerAvailabilityRepository.isTrainerAvailable(
            trainerId,
            groupClass.getStartTime().toLocalDate(),
            groupClass.getStartTime().toLocalTime(),
            groupClass.getEndTime().toLocalTime()
        );

        if (hasOverlap || !isAvailableForClass) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("El entrenador no está disponible en el horario de esta clase.");
        }

        // Asignar entrenador a la clase
        groupClass.setAssignedTrainer(trainer);
        groupClassService.save(groupClass); // Actualizar la clase con el entrenador asignado

        return ResponseEntity.ok("Entrenador asignado a la clase con éxito.");
    }

            
 
}
package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;


import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProfileService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.impl.SubscriptionServiceImpl;

import org.springframework.security.core.Authentication;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;


import jakarta.validation.Valid;



@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService service;

        @Autowired
    private SubscriptionServiceImpl subscriptionService;

    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Autowired
    private PaymentService paymentService;
@Autowired
private TrainerService trainerService;


    @GetMapping
    public List<UserDto> list() {
        System.out.println("ENTRO AL LIST");
        return service.findAll();
    }

    @GetMapping("/page/{page}")
    public ResponseEntity<Page<UserDto>> list(
        @PathVariable Integer page,
        @RequestParam(value = "search", required = false) String search
    ) {
        Pageable pageable = PageRequest.of(page, 6);
        Page<UserDto> usersPage;

        if (search != null && !search.isEmpty()) {
            usersPage = service.findByUsernameContaining(search, pageable);
        } else {
            usersPage = service.findAll(pageable);
            System.out.println("AQUI ESTA EL "+usersPage);
        }
        return ResponseEntity.ok(usersPage);
    }


    @GetMapping("/{id}")
    public ResponseEntity<?> show(@PathVariable Long id) {
        Optional<UserDto> userOption1 = service.findById(id);

        if (userOption1.isPresent()) {
            return ResponseEntity.ok(userOption1.orElseThrow());
        }
        return ResponseEntity.notFound().build();
    }
 

    
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody User user, BindingResult result) {
        System.out.println("=== Datos recibidos para crear usuario ===");
        System.out.println("Username: " + user.getUsername());
        System.out.println("Email: " + user.getEmail());
        System.out.println("Admin: " + user.isAdmin());
        System.out.println("Trainer: " + user.isTrainer());
        System.out.println("Roles: " + user.getRoles());
        System.out.println("Profile Image URL: " + user.getProfileImageUrl());
        if(result.hasErrors()){
            return validation(result);
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(service.save(user));
    }

 

    
    @PutMapping("/{id}")
    public ResponseEntity<?> update(@Valid @RequestBody UserRequest user, BindingResult result, @PathVariable Long id) {
        if(result.hasErrors()){
            return validation(result);
        }
        Optional<UserDto> o = service.update(user, id);
        
        if (o.isPresent()) {
            return ResponseEntity.status(HttpStatus.CREATED).body(o.orElseThrow());
        }
        return ResponseEntity.notFound().build();
    }
    
    

@DeleteMapping("/{id}")
public ResponseEntity<?> remove(@PathVariable Long id) {
    Optional<UserDto> o = service.findById(id);

    if (o.isPresent()) {
        service.remove(id);
        return ResponseEntity.noContent().build(); // 204
    }

    return ResponseEntity.notFound().build();
}

    private ResponseEntity<?> validation(BindingResult result) {
        Map<String, String> errors = new HashMap<>();

        result.getFieldErrors().forEach(err -> {
            errors.put(err.getField(), "El campo " + err.getField() + " " + err.getDefaultMessage());
        });
        return ResponseEntity.badRequest().body(errors);
    }

    // UserController.java

@PostMapping("/register")
public ResponseEntity<?> registerUser(@Valid @RequestBody User user, BindingResult result) {
    if (result.hasErrors()) {
        return validation(result);
    }

    if (service.existsByEmail(user.getEmail())) {
        return ResponseEntity.badRequest().body(Map.of("message", "El correo electrónico ya está en uso"));
    }
    if (service.existsByUsername(user.getUsername())) {
        return ResponseEntity.badRequest().body(Map.of("message", "El nombre de usuario ya está en uso"));
    }

    user.setAdmin(false); // Asegurarse de que no pueda registrarse como admin
    user.setTrainer(false); // Asegurarse de que no pueda registrarse como entrenador

    service.save(user);
    return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("message", "Usuario registrado con éxito"));
}


@GetMapping("/dashboard")
@PreAuthorize("hasRole('USER')")
public ResponseEntity<?> getDashboardInfo(Authentication auth) {
    String email = auth.getName();
    User user = service.findByEmail(email).orElseThrow();

    // Obtener suscripciones de plan
    List<Subscription> planSubs = subscriptionService.getSubscriptionsByUserId(user.getId());
    // Obtener suscripciones de entrenador personal
    List<PersonalTrainerSubscription> trainerSubs = personalTrainerSubscriptionService.getSubscriptionsByUserId(user.getId());
    // Obtener pagos del usuario
    List<PaymentDTO> payments = paymentService.getPaymentsByUserId(user.getId());

    // Crear un objeto de respuesta que muestre ambos estados y los pagos
    Map<String,Object> dashboardData = new HashMap<>();
    dashboardData.put("planSubscriptions", planSubs);
    dashboardData.put("trainerSubscriptions", trainerSubs);
    dashboardData.put("payments", payments); // Agregamos la lista de pagos

    return ResponseEntity.ok(dashboardData);
}

@GetMapping("/personal-trainer")
@PreAuthorize("hasRole('USER')") // Permitir solo a usuarios con rol ROLE_USER
public ResponseEntity<?> getPersonalTrainer(Authentication authentication) {
    String email = authentication.getName();
    Optional<User> userOpt = service.findByEmail(email);
    if (userOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autenticado");
    }
    User user = userOpt.get();

    // Obtener la suscripción activa del usuario
    Optional<PersonalTrainerSubscription> subscriptionOpt = personalTrainerSubscriptionService.findActiveSubscriptionForUser(user.getId());

    if (subscriptionOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No tienes un entrenador personal asignado");
    }

    // Obtener el entrenador personal de la suscripción
    PersonalTrainer trainer = subscriptionOpt.get().getPersonalTrainer();
    return ResponseEntity.ok(trainer);
}



}

package com.sebastian.backend.gymapp.backend_gestorgympro.models;

public interface IUser {
    boolean isAdmin();
    boolean isTrainer();
}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

// package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDate;

public class ActiveClientInfoDTO {
    private Long clientId;
    private String clientName;
    private String clientEmail;
    
    // Si el cliente tiene un Plan activo que incluye a este entrenador:
    private String planName;        // nombre del plan
    private LocalDate planStart;    // fecha inicio
    private LocalDate planEnd;      // fecha fin

    // Si el cliente tiene un "trainer only" (PersonalTrainerSubscription):
    private LocalDate trainerStart;
    private LocalDate trainerEnd;

    // Podrías agregar más campos: si está activo, etc.

    // Getters y setters
    // (o usa Lombok @Data)
    public Long getClientId() {
        return clientId;
    }
    public void setClientId(Long clientId) {
        this.clientId = clientId;
    }

    public String getClientName() {
        return clientName;
    }
    public void setClientName(String clientName) {
        this.clientName = clientName;
    }
    
    public String getClientEmail() {
        return clientEmail;
    }
    public void setClientEmail(String clientEmail) {
        this.clientEmail = clientEmail;
    }

    public String getPlanName() {
        return planName;
    }
    public void setPlanName(String planName) {
        this.planName = planName;
    }

    public LocalDate getPlanStart() {
        return planStart;
    }
    public void setPlanStart(LocalDate planStart) {
        this.planStart = planStart;
    }

    public LocalDate getPlanEnd() {
        return planEnd;
    }
    public void setPlanEnd(LocalDate planEnd) {
        this.planEnd = planEnd;
    }

    public LocalDate getTrainerStart() {
        return trainerStart;
    }
    public void setTrainerStart(LocalDate trainerStart) {
        this.trainerStart = trainerStart;
    }

    public LocalDate getTrainerEnd() {
        return trainerEnd;
    }
    public void setTrainerEnd(LocalDate trainerEnd) {
        this.trainerEnd = trainerEnd;
    }
}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDateTime;

public class BodyMeasurementDto {

    private Integer age; 

    private String clientName;

    // Getters y Setters
    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public Integer getAge() {
        return age;
    }
    public void setAge(Integer age) {
        this.age = age;
    }
    private Double weight;
    private Double height;
    private Double bodyFatPercentage;
    private LocalDateTime date;

    private String injuries;
    private String medications;
    private String otherHealthInfo;

    private Boolean currentlyExercising;
    private String sportsPracticed;

    private Double currentWeight;
    private Double bmi;

    private Double relaxedArm;
    private Double waist;
    private Double midThigh;
    private Double flexedArm;
    private Double hips;
    private Double calf;

    private Double tricepFold;
    private Double subscapularFold;
    private Double bicepFold;
    private Double suprailiacFold;

    private Double sumOfFolds;
    private Double percentageOfFolds;
    private Double fatMass;
    private Double leanMass;
    private Double muscleMass;

    private Double idealMinWeight;
    private Double idealMaxWeight;
    private String trainerRecommendations;

    public Double getWeight() {
        return weight;
    }
    public void setWeight(Double weight) {
        this.weight = weight;
    }
    public Double getHeight() {
        return height;
    }
    public void setHeight(Double height) {
        this.height = height;
    }
    public Double getBodyFatPercentage() {
        return bodyFatPercentage;
    }
    public void setBodyFatPercentage(Double bodyFatPercentage) {
        this.bodyFatPercentage = bodyFatPercentage;
    }
    public LocalDateTime getDate() {
        return date;
    }
    public void setDate(LocalDateTime date) {
        this.date = date;
    }
    public String getInjuries() {
        return injuries;
    }
    public void setInjuries(String injuries) {
        this.injuries = injuries;
    }
    public String getMedications() {
        return medications;
    }
    public void setMedications(String medications) {
        this.medications = medications;
    }
    public String getOtherHealthInfo() {
        return otherHealthInfo;
    }
    public void setOtherHealthInfo(String otherHealthInfo) {
        this.otherHealthInfo = otherHealthInfo;
    }
    public Boolean getCurrentlyExercising() {
        return currentlyExercising;
    }
    public void setCurrentlyExercising(Boolean currentlyExercising) {
        this.currentlyExercising = currentlyExercising;
    }
    public String getSportsPracticed() {
        return sportsPracticed;
    }
    public void setSportsPracticed(String sportsPracticed) {
        this.sportsPracticed = sportsPracticed;
    }
    public Double getCurrentWeight() {
        return currentWeight;
    }
    public void setCurrentWeight(Double currentWeight) {
        this.currentWeight = currentWeight;
    }
    public Double getBmi() {
        return bmi;
    }
    public void setBmi(Double bmi) {
        this.bmi = bmi;
    }
    public Double getRelaxedArm() {
        return relaxedArm;
    }
    public void setRelaxedArm(Double relaxedArm) {
        this.relaxedArm = relaxedArm;
    }
    public Double getWaist() {
        return waist;
    }
    public void setWaist(Double waist) {
        this.waist = waist;
    }
    public Double getMidThigh() {
        return midThigh;
    }
    public void setMidThigh(Double midThigh) {
        this.midThigh = midThigh;
    }
    public Double getFlexedArm() {
        return flexedArm;
    }
    public void setFlexedArm(Double flexedArm) {
        this.flexedArm = flexedArm;
    }
    public Double getHips() {
        return hips;
    }
    public void setHips(Double hips) {
        this.hips = hips;
    }
    public Double getCalf() {
        return calf;
    }
    public void setCalf(Double calf) {
        this.calf = calf;
    }
    public Double getTricepFold() {
        return tricepFold;
    }
    public void setTricepFold(Double tricepFold) {
        this.tricepFold = tricepFold;
    }
    public Double getSubscapularFold() {
        return subscapularFold;
    }
    public void setSubscapularFold(Double subscapularFold) {
        this.subscapularFold = subscapularFold;
    }
    public Double getBicepFold() {
        return bicepFold;
    }
    public void setBicepFold(Double bicepFold) {
        this.bicepFold = bicepFold;
    }
    public Double getSuprailiacFold() {
        return suprailiacFold;
    }
    public void setSuprailiacFold(Double suprailiacFold) {
        this.suprailiacFold = suprailiacFold;
    }
    public Double getSumOfFolds() {
        return sumOfFolds;
    }
    public void setSumOfFolds(Double sumOfFolds) {
        this.sumOfFolds = sumOfFolds;
    }
    public Double getPercentageOfFolds() {
        return percentageOfFolds;
    }
    public void setPercentageOfFolds(Double percentageOfFolds) {
        this.percentageOfFolds = percentageOfFolds;
    }
    public Double getFatMass() {
        return fatMass;
    }
    public void setFatMass(Double fatMass) {
        this.fatMass = fatMass;
    }
    public Double getLeanMass() {
        return leanMass;
    }
    public void setLeanMass(Double leanMass) {
        this.leanMass = leanMass;
    }
    public Double getMuscleMass() {
        return muscleMass;
    }
    public void setMuscleMass(Double muscleMass) {
        this.muscleMass = muscleMass;
    }
    public Double getIdealMinWeight() {
        return idealMinWeight;
    }
    public void setIdealMinWeight(Double idealMinWeight) {
        this.idealMinWeight = idealMinWeight;
    }
    public Double getIdealMaxWeight() {
        return idealMaxWeight;
    }
    public void setIdealMaxWeight(Double idealMaxWeight) {
        this.idealMaxWeight = idealMaxWeight;
    }
    public String getTrainerRecommendations() {
        return trainerRecommendations;
    }
    public void setTrainerRecommendations(String trainerRecommendations) {
        this.trainerRecommendations = trainerRecommendations;
    }

    // Getters y Setters
    // ...
}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDateTime;

public class CalendarEventDTO {
    private Long id;               
    private String title;          
    private LocalDateTime start;  
    private LocalDateTime end;     
    private String eventType;
    
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getTitle() {
        return title;
    }
    public void setTitle(String title) {
        this.title = title;
    }
    public LocalDateTime getStart() {
        return start;
    }
    public void setStart(LocalDateTime start) {
        this.start = start;
    }
    public LocalDateTime getEnd() {
        return end;
    }
    public void setEnd(LocalDateTime end) {
        this.end = end;
    }
    public String getEventType() {
        return eventType;
    }
    public void setEventType(String eventType) {
        this.eventType = eventType;
    }      


}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.math.BigDecimal;

public class CartItemDTO {
        private Long productId;
        private int quantity;
        private String name; 
        private BigDecimal unitPrice; 
        
        public Long getProductId() {
            return productId;
        }
        public void setProductId(Long productId) {
            this.productId = productId;
        }
        public int getQuantity() {
            return quantity;
        }
        public void setQuantity(int quantity) {
            this.quantity = quantity;
        }
        public String getName() {
            return name;
        }
        public void setName(String name) {
            this.name = name;
        }
        public BigDecimal getUnitPrice() {
            return unitPrice;
        }
        public void setUnitPrice(BigDecimal unitPrice) {
            this.unitPrice = unitPrice;
        }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import jakarta.validation.constraints.NotBlank;

public class CategoryDto {

    @NotBlank(message = "El nombre de la categoría no puede estar vacío")
    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDateTime;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;

public class GroupClassDto {
    private Long id;
    private String className;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private int maxParticipants;
    private int availableSlots; // Cupos disponibles

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public LocalDateTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalDateTime startTime) {
        this.startTime = startTime;
    }

    public LocalDateTime getEndTime() {
        return endTime;
    }

    public void setEndTime(LocalDateTime endTime) {
        this.endTime = endTime;
    }

    public int getMaxParticipants() {
        return maxParticipants;
    }

    public void setMaxParticipants(int maxParticipants) {
        this.maxParticipants = maxParticipants;
    }

    public int getAvailableSlots() {
        return availableSlots;
    }

    public void setAvailableSlots(int availableSlots) {
        this.availableSlots = availableSlots;
    }

    public GroupClassDto(GroupClass groupClass, long currentBookings) {
        this.id = groupClass.getId();
        this.className = groupClass.getClassName();
        this.startTime = groupClass.getStartTime();
        this.endTime = groupClass.getEndTime();
        this.maxParticipants = groupClass.getMaxParticipants();
        this.availableSlots = (int) (groupClass.getMaxParticipants() - currentBookings);
    }

    // Getters y Setters...
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;



import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

public class PaymentDTO {
    private Long id;
    private String planName;
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getPlanName() {
        return planName;
    }
    public void setPlanName(String planName) {
        this.planName = planName;
    }
    public LocalDateTime getPaymentDate() {
        return paymentDate;
    }
    public void setPaymentDate(LocalDateTime paymentDate) {
        this.paymentDate = paymentDate;
    }
    public String getPaymentMethod() {
        return paymentMethod;
    }
    public void setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
    }
    public BigDecimal getTransactionAmount() {
        return transactionAmount;
    }
    public void setTransactionAmount(BigDecimal transactionAmount) {
        this.transactionAmount = transactionAmount;
    }
    public LocalDate getSubscriptionStartDate() {
        return subscriptionStartDate;
    }
    public void setSubscriptionStartDate(LocalDate subscriptionStartDate) {
        this.subscriptionStartDate = subscriptionStartDate;
    }
    public LocalDate getSubscriptionEndDate() {
        return subscriptionEndDate;
    }
    public void setSubscriptionEndDate(LocalDate subscriptionEndDate) {
        this.subscriptionEndDate = subscriptionEndDate;
    }
    private LocalDateTime paymentDate;
    private String paymentMethod;
    private BigDecimal transactionAmount;
    private LocalDate subscriptionStartDate;
    private LocalDate subscriptionEndDate;

    // Getters y Setters
    // ...
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

public class PersonalTrainerDto {
    private Long id;
    private String username;
    private String email;
    private String specialization;
    private Integer experienceYears;
    
    private Boolean availability;
    private String profileImageUrl;

    // Nuevos campos
    private String title;
    private String studies;
    private String certifications;
    private String description;

    public PersonalTrainerDto(Long id, String username, String email, String specialization,
    Integer experienceYears, Boolean availability, String profileImageUrl,
    String title, String studies, String certifications, String description) {
    this.id = id;
    this.username = username;
    this.email = email;
    this.specialization = specialization;
    this.experienceYears = experienceYears;
    this.availability = availability;
    this.profileImageUrl = profileImageUrl;
    this.title = title;
    this.studies = studies;
    this.certifications = certifications;
    this.description = description;
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSpecialization() {
        return specialization;
    }

    public void setSpecialization(String specialization) {
        this.specialization = specialization;
    }

    public Integer getExperienceYears() {
        return experienceYears;
    }

    public void setExperienceYears(Integer experienceYears) {
        this.experienceYears = experienceYears;
    }

    public Boolean getAvailability() {
        return availability;
    }

    public void setAvailability(Boolean availability) {
        this.availability = availability;
    }

    public String getProfileImageUrl() {
        return profileImageUrl;
    }

    public void setProfileImageUrl(String profileImageUrl) {
        this.profileImageUrl = profileImageUrl;
    }



    // Getters y Setters para los nuevos campos
    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getStudies() {
        return studies;
    }

    public void setStudies(String studies) {
        this.studies = studies;
    }

    public String getCertifications() {
        return certifications;
    }

    public void setCertifications(String certifications) {
        this.certifications = certifications;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    // Resto de getters y setters existentes...
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

public class ProductDto {
    private String name;
    private String description;
    private String category;
    private Double price;
    
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public String getCategory() {
        return category;
    }
    public void setCategory(String category) {
        this.category = category;
    }
    public Double getPrice() {
        return price;
    }
    public void setPrice(Double price) {
        this.price = price;
    }

}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDateTime;

public class TimeSlotDTO {
    private Long trainerId;
    private LocalDateTime startDateTime;
    private LocalDateTime endDateTime;
    private boolean available;

    // Getters y setters
    public Long getTrainerId() {
        return trainerId;
    }

    public void setTrainerId(Long trainerId) {
        this.trainerId = trainerId;
    }

    public LocalDateTime getStartDateTime() {
        return startDateTime;
    }

    public void setStartDateTime(LocalDateTime startDateTime) {
        this.startDateTime = startDateTime;
    }

    public LocalDateTime getEndDateTime() {
        return endDateTime;
    }

    public void setEndDateTime(LocalDateTime endDateTime) {
        this.endDateTime = endDateTime;
    }

    public boolean isAvailable() {
        return available;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.math.BigDecimal;

public class TrainerAssignmentRequest {
    private String specialization;
    private Integer experienceYears;
    private Boolean availability;
    private BigDecimal monthlyFee;

    // Nuevos campos
    private String title;
    private String studies;
    private String certifications;
    private String description;

    // Getters y Setters de todos los campos
    public String getSpecialization() { return specialization; }
    public void setSpecialization(String specialization) { this.specialization = specialization; }

    public Integer getExperienceYears() { return experienceYears; }
    public void setExperienceYears(Integer experienceYears) { this.experienceYears = experienceYears; }

    public Boolean getAvailability() { return availability; }
    public void setAvailability(Boolean availability) { this.availability = availability; }

    public BigDecimal getMonthlyFee() { return monthlyFee; }
    public void setMonthlyFee(BigDecimal monthlyFee) { this.monthlyFee = monthlyFee; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getStudies() { return studies; }
    public void setStudies(String studies) { this.studies = studies; }

    public String getCertifications() { return certifications; }
    public void setCertifications(String certifications) { this.certifications = certifications; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}
// src/main/java/com/sebastian/backend/gymapp/backend_gestorgympro/models/dto/TrainerAvailabilityRequest.java
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDate;
import java.time.LocalTime;

public class TrainerAvailabilityRequest {
    private LocalDate day;
    private LocalTime startTime;
    private LocalTime endTime;

    // Getters y Setters
    public LocalDate getDay() {
        return day;
    }

    public void setDay(LocalDate day) {
        this.day = day;
    }

    public LocalTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalTime startTime) {
        this.startTime = startTime;
    }

    public LocalTime getEndTime() {
        return endTime;
    }

    public void setEndTime(LocalTime endTime) {
        this.endTime = endTime;
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.math.BigDecimal;

public class TrainerUpdateRequest {
        private String title;
    private String studies;
    private String certifications;
    private String description;
    private BigDecimal monthlyFee;
    public String getTitle() {
        return title;
    }
    public void setTitle(String title) {
        this.title = title;
    }
    public String getStudies() {
        return studies;
    }
    public void setStudies(String studies) {
        this.studies = studies;
    }
    public String getCertifications() {
        return certifications;
    }
    public void setCertifications(String certifications) {
        this.certifications = certifications;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public BigDecimal getMonthlyFee() {
        return monthlyFee;
    }
    public void setMonthlyFee(BigDecimal monthlyFee) {
        this.monthlyFee = monthlyFee;
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

public class UserDto {
    private Long id;
    private String username;
    private String email;
    private boolean admin;
    private boolean trainer;
    private String profileImageUrl; 

    public String getProfileImageUrl() {
        return profileImageUrl;
    }
    public void setProfileImageUrl(String profileImageUrl) {
        this.profileImageUrl = profileImageUrl;
    }
    public boolean isTrainer() {
        return trainer;
    }
    public void setTrainer(boolean trainer) {
        this.trainer = trainer;
    }
    public boolean isAdmin() {
        return admin;
    }
    public void setAdmin(boolean admin) {
        this.admin = admin;
    }
    public UserDto(Long id, String username, String email, boolean admin, boolean trainer, String profileImageUrl) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.admin = admin;
        this.trainer = trainer;
        this.profileImageUrl = profileImageUrl;
    }
    public UserDto() {
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;

public class DtoMapperPersonalTrainer {

    private PersonalTrainer personalTrainer;

    private DtoMapperPersonalTrainer() {}

    public static DtoMapperPersonalTrainer builder() {
        return new DtoMapperPersonalTrainer();
    }

    public DtoMapperPersonalTrainer setPersonalTrainer(PersonalTrainer personalTrainer) {
        this.personalTrainer = personalTrainer;
        return this;
    }

    public PersonalTrainerDto build() {
        if (personalTrainer == null) {
            throw new RuntimeException("Debe pasar el entity personalTrainer!");
        }
        return new PersonalTrainerDto(
                personalTrainer.getId(),
                personalTrainer.getSpecialization(),
                personalTrainer.getExperienceYears(),
                personalTrainer.getAvailability()
        );
    }
}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

public class DtoMapperUser {

    private User user;

    
    private DtoMapperUser() {
    }

    public static DtoMapperUser builder() {
        return new DtoMapperUser();
    }

    public DtoMapperUser setUser(User user) {
        this.user = user;
        return this;
    }

    public UserDto build() {
        if (user == null) {
            throw new RuntimeException("Debe pasar el entity user!");
        }
        boolean isAdmin = user.getRoles().stream().anyMatch(r -> "ROLE_ADMIN".equals(r.getName()));
        boolean isTrainer = user.getRoles().stream().anyMatch(r -> "ROLE_TRAINER".equals(r.getName()));
        return new UserDto(
            this.user.getId(),
            user.getUsername(),
            user.getEmail(),
            isAdmin,
            isTrainer,
            user.getProfileImageUrl() // Asignar la URL de la imagen
        );
    }
    

}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "body_measurements")
public class BodyMeasurement {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private User client;

    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private User trainer;

    private String clientName;
  
 
  
    private Double weight; // Peso en kg
    private Double height; // Altura en cm
    private Double bodyFatPercentage; // Porcentaje de grasa corporal
    private LocalDateTime date; // Fecha de evaluación

    // Información de salud
    private String injuries; // Lesiones
    private String medications; // Medicamentos
    private String otherHealthInfo; // Otros

    // Información deportiva
    private Boolean currentlyExercising; // Ejercita actualmente
    private String sportsPracticed; // Deportes que practica

    // Información IMC
    private Double currentWeight; // Peso actual
    private Double bmi; // IMC

    // Perímetros corporales
    private Double relaxedArm; // Brazo relajado
    private Double waist; // Cintura
    private Double midThigh; // Muslo medio
    private Double flexedArm; // Brazo en contracción
    private Double hips; // Cadera
    private Double calf; // Pantorrilla

    // Perfil antropométrico
    private Double tricepFold;
    private Double subscapularFold;
    private Double bicepFold;
    private Double suprailiacFold;

    // Interpretación de datos
    private Double sumOfFolds;
    private Double percentageOfFolds;
    private Double fatMass;
    private Double leanMass;
    private Double muscleMass;

    // Peso ideal
    private Double idealMinWeight;
    private Double idealMaxWeight;
    private String trainerRecommendations;

    private Integer age;

    public String getClientName() {
        return clientName;
    }
    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public Integer getAge() {
        return age;
    }
    public void setAge(Integer age) {
        this.age = age;
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public User getClient() {
        return client;
    }
    public void setClient(User client) {
        this.client = client;
    }
    public User getTrainer() {
        return trainer;
    }
    public void setTrainer(User trainer) {
        this.trainer = trainer;
    }
    public Double getWeight() {
        return weight;
    }
    public void setWeight(Double weight) {
        this.weight = weight;
    }
    public Double getHeight() {
        return height;
    }
    public void setHeight(Double height) {
        this.height = height;
    }
    public Double getBodyFatPercentage() {
        return bodyFatPercentage;
    }
    public void setBodyFatPercentage(Double bodyFatPercentage) {
        this.bodyFatPercentage = bodyFatPercentage;
    }
    public LocalDateTime getDate() {
        return date;
    }
    public void setDate(LocalDateTime date) {
        this.date = date;
    }
    public String getInjuries() {
        return injuries;
    }
    public void setInjuries(String injuries) {
        this.injuries = injuries;
    }
    public String getMedications() {
        return medications;
    }
    public void setMedications(String medications) {
        this.medications = medications;
    }
    public String getOtherHealthInfo() {
        return otherHealthInfo;
    }
    public void setOtherHealthInfo(String otherHealthInfo) {
        this.otherHealthInfo = otherHealthInfo;
    }
    public Boolean getCurrentlyExercising() {
        return currentlyExercising;
    }
    public void setCurrentlyExercising(Boolean currentlyExercising) {
        this.currentlyExercising = currentlyExercising;
    }
    public String getSportsPracticed() {
        return sportsPracticed;
    }
    public void setSportsPracticed(String sportsPracticed) {
        this.sportsPracticed = sportsPracticed;
    }
    public Double getCurrentWeight() {
        return currentWeight;
    }
    public void setCurrentWeight(Double currentWeight) {
        this.currentWeight = currentWeight;
    }
    public Double getBmi() {
        return bmi;
    }
    public void setBmi(Double bmi) {
        this.bmi = bmi;
    }
    public Double getRelaxedArm() {
        return relaxedArm;
    }
    public void setRelaxedArm(Double relaxedArm) {
        this.relaxedArm = relaxedArm;
    }
    public Double getWaist() {
        return waist;
    }
    public void setWaist(Double waist) {
        this.waist = waist;
    }
    public Double getMidThigh() {
        return midThigh;
    }
    public void setMidThigh(Double midThigh) {
        this.midThigh = midThigh;
    }
    public Double getFlexedArm() {
        return flexedArm;
    }
    public void setFlexedArm(Double flexedArm) {
        this.flexedArm = flexedArm;
    }
    public Double getHips() {
        return hips;
    }
    public void setHips(Double hips) {
        this.hips = hips;
    }
    public Double getCalf() {
        return calf;
    }
    public void setCalf(Double calf) {
        this.calf = calf;
    }
    public Double getTricepFold() {
        return tricepFold;
    }
    public void setTricepFold(Double tricepFold) {
        this.tricepFold = tricepFold;
    }
    public Double getSubscapularFold() {
        return subscapularFold;
    }
    public void setSubscapularFold(Double subscapularFold) {
        this.subscapularFold = subscapularFold;
    }
    public Double getBicepFold() {
        return bicepFold;
    }
    public void setBicepFold(Double bicepFold) {
        this.bicepFold = bicepFold;
    }
    public Double getSuprailiacFold() {
        return suprailiacFold;
    }
    public void setSuprailiacFold(Double suprailiacFold) {
        this.suprailiacFold = suprailiacFold;
    }
    public Double getSumOfFolds() {
        return sumOfFolds;
    }
    public void setSumOfFolds(Double sumOfFolds) {
        this.sumOfFolds = sumOfFolds;
    }
    public Double getPercentageOfFolds() {
        return percentageOfFolds;
    }
    public void setPercentageOfFolds(Double percentageOfFolds) {
        this.percentageOfFolds = percentageOfFolds;
    }
    public Double getFatMass() {
        return fatMass;
    }
    public void setFatMass(Double fatMass) {
        this.fatMass = fatMass;
    }
    public Double getLeanMass() {
        return leanMass;
    }
    public void setLeanMass(Double leanMass) {
        this.leanMass = leanMass;
    }
    public Double getMuscleMass() {
        return muscleMass;
    }
    public void setMuscleMass(Double muscleMass) {
        this.muscleMass = muscleMass;
    }
    public Double getIdealMinWeight() {
        return idealMinWeight;
    }
    public void setIdealMinWeight(Double idealMinWeight) {
        this.idealMinWeight = idealMinWeight;
    }
    public Double getIdealMaxWeight() {
        return idealMaxWeight;
    }
    public void setIdealMaxWeight(Double idealMaxWeight) {
        this.idealMaxWeight = idealMaxWeight;
    }
    public String getTrainerRecommendations() {
        return trainerRecommendations;
    }
    public void setTrainerRecommendations(String trainerRecommendations) {
        this.trainerRecommendations = trainerRecommendations;
    }

    // Getters y Setters
    // ...
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "bookings")
public class Booking {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Quién reserva (User)
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Entrenador asignado (puede ser inferido desde el timeslot)
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private PersonalTrainer trainer;

    // Fecha y hora específica del slot reservado
    @Column(name = "start_date_time", nullable = false)
    private LocalDateTime startDateTime;

    @Column(name = "end_date_time", nullable = false)
    private LocalDateTime endDateTime;

    // ... otros campos que necesites

    public Long getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
         this.user = user;
    }

    public PersonalTrainer getTrainer() {
         return trainer;
    }

    public void setTrainer(PersonalTrainer trainer) {
         this.trainer = trainer;
    }

    public LocalDateTime getStartDateTime() {
         return startDateTime;
    }

    public void setStartDateTime(LocalDateTime startDateTime) {
         this.startDateTime = startDateTime;
    }

    public LocalDateTime getEndDateTime() {
         return endDateTime;
    }

    public void setEndDateTime(LocalDateTime endDateTime) {
         this.endDateTime = endDateTime;
    }
}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "carousel_images")
public class CarouselImage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="image_url", nullable = false)
    private String imageUrl;

    @Column(name="caption")
    private String caption;

    // Cambiar 'order' a 'orderNumber'
    @Column(name="order_number", nullable = false)
    private Integer orderNumber;

    // Constructor vacío
    public CarouselImage() {}

    // Getters y Setters

    public Long getId() {
        return id;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public String getCaption() {
        return caption;
    }

    public Integer getOrderNumber() {
        return orderNumber;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }

    public void setCaption(String caption) {
        this.caption = caption;
    }

    public void setOrderNumber(Integer orderNumber) {
        this.orderNumber = orderNumber;
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Entity
@Table(name = "categories")
public class Category {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String name; // Ej: "Proteina", "Creatina", "Vitaminas", etc.

    @OneToMany(mappedBy = "category", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<Product> products = new ArrayList<>();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<Product> getProducts() {
        return products;
    }

    public void setProducts(List<Product> products) {
        this.products = products;
    }

    
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "payments")
public class Payment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Relación muchos a uno con User
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Relación muchos a uno con Plan
    @ManyToOne
    @JoinColumn(name = "plan_id", nullable = true)
    private Plan plan;

    @OneToOne(mappedBy = "payment")
    private Subscription subscription;

    @Column(name = "mercado_pago_id", nullable = true)
    private String mercadoPagoId;

    private String status; 

    @Column(name = "transaction_amount")
    private BigDecimal transactionAmount;

    @Column(name = "payment_method")
    private String paymentMethod;

    @Column(name = "payment_date")
    private LocalDateTime paymentDate;

    @Column(name = "update_date")
    private LocalDateTime updateDate;

    @Column(name = "external_reference")
    private String externalReference;

    @Column(name = "trainer_id", nullable = true)
    private Long trainerId;

    @Column(name = "plan_included", nullable = false)
    private boolean planIncluded = false;

    @Column(name = "trainer_included", nullable = false)
    private boolean trainerIncluded = false;



        // Getters y Setters
        public Long getTrainerId() { return trainerId; }

        public void setTrainerId(Long trainerId) { this.trainerId = trainerId; }

        public boolean isPlanIncluded() { return planIncluded; }

        public void setPlanIncluded(boolean planIncluded) { this.planIncluded = planIncluded; }

        public boolean isTrainerIncluded() { return trainerIncluded; }

        public void setTrainerIncluded(boolean trainerIncluded) { this.trainerIncluded = trainerIncluded; }

    
    public void setExternalReference(String externalReference) {
        this.externalReference = externalReference;
    }

    public Long getId() {
        return id;
    }
    public String getExternalReference() {
        return externalReference;
    }
    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Plan getPlan() {
        return plan;
    }

    public void setPlan(Plan plan) {
        this.plan = plan;
    }

    public String getMercadoPagoId() {
        return mercadoPagoId;
    }

    public void setMercadoPagoId(String mercadoPagoId) {
        this.mercadoPagoId = mercadoPagoId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public BigDecimal getTransactionAmount() {
        return transactionAmount;
    }

    public void setTransactionAmount(BigDecimal transactionAmount) {
        this.transactionAmount = transactionAmount;
    }

    public String getPaymentMethod() {
        return paymentMethod;
    }

    public void setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
    }

    public LocalDateTime getPaymentDate() {
        return paymentDate;
    }

    public void setPaymentDate(LocalDateTime paymentDate) {
        this.paymentDate = paymentDate;
    }

    public LocalDateTime getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(LocalDateTime updateDate) {
        this.updateDate = updateDate;
    }

  
  
}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import java.math.BigDecimal;
import java.util.List;

import jakarta.persistence.*;

@Entity
@Table(name = "personal_trainer")
public class PersonalTrainer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String specialization;

    @Column(name = "experience_years", nullable = false)
    private Integer experienceYears;

    @Column(nullable = false)
    private Boolean availability;  // Cambia el tipo de String a Boolean

    @OneToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "monthly_fee", nullable = false)
    private BigDecimal monthlyFee;

    // Nuevos campos
    @Column(name = "title", nullable = true)
    private String title;

    @Column(name = "studies", nullable = true, length = 2000)
    private String studies;

    @Column(name = "certifications", nullable = true, length = 2000)
    private String certifications;

    @Column(name = "description", nullable = true, length = 2000)
    private String description;

        // Relación Many-to-Many con Plan
        @ManyToMany(mappedBy = "includedTrainers")
        private List<Plan> plans;

    public List<Plan> getPlans() {
            return plans;
        }

        public void setPlans(List<Plan> plans) {
            this.plans = plans;
        }

    // Getters y Setters para los nuevos campos
    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getStudies() {
        return studies;
    }

    public void setStudies(String studies) {
        this.studies = studies;
    }

    public String getCertifications() {
        return certifications;
    }

    public void setCertifications(String certifications) {
        this.certifications = certifications;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public BigDecimal getMonthlyFee() {
        return monthlyFee;
    }

    public void setMonthlyFee(BigDecimal monthlyFee) {
        this.monthlyFee = monthlyFee;
    }

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSpecialization() {
        return specialization;
    }

    public void setSpecialization(String specialization) {
        this.specialization = specialization;
    }

    public Integer getExperienceYears() {
        return experienceYears;
    }

    public void setExperienceYears(Integer experienceYears) {
        this.experienceYears = experienceYears;
    }

    public Boolean getAvailability() {
        return availability;
    }

    public void setAvailability(Boolean availability) {  // Cambia aquí a Boolean
        this.availability = availability;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import java.time.LocalDate;

import jakarta.persistence.*;

@Entity
@Table(name = "personal_trainer_subscriptions")
public class PersonalTrainerSubscription {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;



    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private PersonalTrainer personalTrainer;

    @OneToOne
    @JoinColumn(name = "payment_id")
    private Payment payment;

    @Column(name = "start_date", nullable = false)
    private LocalDate startDate;

    @Column(name = "end_date", nullable = false)
    private LocalDate endDate;

    private Boolean active;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public PersonalTrainer getPersonalTrainer() {
        return personalTrainer;
    }

    public void setPersonalTrainer(PersonalTrainer personalTrainer) {
        this.personalTrainer = personalTrainer;
    }

    public Payment getPayment() {
        return payment;
    }

    public void setPayment(Payment payment) {
        this.payment = payment;
    }

    public LocalDate getStartDate() {
        return startDate;
    }

    public void setStartDate(LocalDate startDate) {
        this.startDate = startDate;
    }

    public LocalDate getEndDate() {
        return endDate;
    }

    public void setEndDate(LocalDate endDate) {
        this.endDate = endDate;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }
}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;

import java.math.BigDecimal;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "plans")
public class Plan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;



    private String name; // Ejemplo: "Mensual", "Trimestral", "Anual"

    private BigDecimal price; // Precio del plan

    private String description;

    @Column(nullable = true)
    private Integer discount; // Porcentaje de descuento

    // Un Plan tiene muchos Payment. Un Payment pertenece a un Plan.
    @OneToMany(mappedBy = "plan")
    @JsonIgnore
    private List<Payment> payments;
    
    // Relación uno a muchos con Subscription
    @OneToMany(mappedBy = "plan")
    @JsonIgnore 
    private List<Subscription> subscriptions;

        // Relación Many-to-Many con PersonalTrainer
        @ManyToMany
        @JoinTable(
            name = "plans_trainers",
            joinColumns = @JoinColumn(name = "plan_id"),
            inverseJoinColumns = @JoinColumn(name = "trainer_id")
        )
        @JsonIgnore // Evita recursión infinita al serializar
        private List<PersonalTrainer> includedTrainers;

    public List<PersonalTrainer> getIncludedTrainers() {
            return includedTrainers;
        }

        public void setIncludedTrainers(List<PersonalTrainer> includedTrainers) {
            this.includedTrainers = includedTrainers;
        }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public  BigDecimal getPrice() {
        return price;
    }

    public void setPrice( BigDecimal price) {
        this.price = price;
    }

    public List<Payment> getPayments() {
        return payments;
    }

    public void setPayments(List<Payment> payments) {
        this.payments = payments;
    }

    public List<Subscription> getSubscriptions() {
        return subscriptions;
    }

    public void setSubscriptions(List<Subscription> subscriptions) {
        this.subscriptions = subscriptions;
    }


    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Integer getDiscount() {
        return discount;
    }

    public void setDiscount(Integer discount) {
        this.discount = discount;
    }


    
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "products")
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String description;

    private BigDecimal price;

    private String imageUrl;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @ManyToOne
    @JoinColumn(name = "category_id")
    private Category category;

    public Category getCategory() {
        return category;
    }

    public void setCategory(Category category) {
        this.category = category;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public BigDecimal getPrice() {
        return price;
    }

    public void setPrice(BigDecimal price) {
        this.price = price;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }


    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "roles")
public class Role {

    public Role(){

    }

    public Role(String name) {
        this.name = name;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String name;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "routines")
public class Routine {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Cliente al que pertenece la rutina
    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private User client;

    // Entrenador que asigna la rutina
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private User trainer;

    private String title;
    private String description;
    private LocalDateTime assignedDate;

    // Getters y Setters
    // ...
}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;


import jakarta.persistence.*;
import java.time.LocalDate;

@Entity
@Table(name = "subscriptions")
public class Subscription {
    
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
    
        // Relación muchos a uno con User
        @ManyToOne
        @JoinColumn(name = "user_id", nullable = false)
        private User user;
    
        // Relación muchos a uno con Plan
        @ManyToOne
        @JoinColumn(name = "plan_id", nullable = false)
        private Plan plan;

        @OneToOne
        @JoinColumn(name = "payment_id")
        private Payment payment;
    
        public Payment getPayment() {
            return payment;
        }

        public void setPayment(Payment payment) {
            this.payment = payment;
        }

        @Column(name = "start_date", nullable = false)
        private LocalDate startDate;
    
        @Column(name = "end_date", nullable = false)
        private LocalDate endDate;
    
        private Boolean active;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Plan getPlan() {
        return plan;
    }

    public void setPlan(Plan plan) {
        this.plan = plan;
    }

    public LocalDate getStartDate() {
        return startDate;
    }

    public void setStartDate(LocalDate startDate) {
        this.startDate = startDate;
    }

    public LocalDate getEndDate() {
        return endDate;
    }

    public void setEndDate(LocalDate endDate) {
        this.endDate = endDate;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }


}

package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.time.LocalDate;
import java.time.LocalTime;

@Entity
@Table(name = "trainer_availability")
public class TrainerAvailability {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Relación con el entrenador (PersonalTrainer)
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private PersonalTrainer trainer;

    @Column(name = "day", nullable = false)
    private LocalDate day;

    @Column(name = "start_time", nullable = false)
    private LocalTime startTime;

    @Column(name = "end_time", nullable = false)
    private LocalTime endTime;

    // Getters y Setters

    public Long getId() {
        return id;
    }

    public PersonalTrainer getTrainer() {
        return trainer;
    }

    public void setTrainer(PersonalTrainer trainer) {
        this.trainer = trainer;
    }

    public LocalDate getDay() {
        return day;
    }

    public void setDay(LocalDate day) {
        this.day = day;
    }

    public LocalTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalTime startTime) {
        this.startTime = startTime;
    }

    public LocalTime getEndTime() {
        return endTime;
    }

    public void setEndTime(LocalTime endTime) {
        this.endTime = endTime;
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;

@Entity
@Table(name = "trainer_clients")
public class TrainerClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // El entrenador (PersonalTrainer)
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private PersonalTrainer trainer;

    // El cliente (User)
    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private User client;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public PersonalTrainer getTrainer() {
        return trainer;
    }

    public void setTrainer(PersonalTrainer trainer) {
        this.trainer = trainer;
    }

    public User getClient() {
        return client;
    }

    public void setClient(User client) {
        this.client = client;
    }


}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;

import java.util.List;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.IUser;


@Entity
@Table(name="users")
public class User implements IUser  {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    

    @NotBlank
    @Column(unique = true)
    private String username;

    @NotBlank
    private String password;

    @NotEmpty
    @Email
    @Column(unique = true)
    private String email;

    @ManyToMany
    @JoinTable(
    name = "users_roles",
    joinColumns = @JoinColumn(name = "user_id"),
    inverseJoinColumns = @JoinColumn(name = "role_id"),
    uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "role_id"})
    )

    private List<Role> roles;

      // Nueva relación uno a muchos con Payment
    @OneToMany(mappedBy = "user")
     private List<Payment> payments;

      // Nueva relación uno a muchos con Subscription
    @OneToMany(mappedBy = "user")
    private List<Subscription> subscriptions;

    @Transient //un campo que es de la clase, que no se mapea a la base de datos como una columna
    private boolean admin;

    @Transient
    private boolean trainer; // Agregar este campo

    @Column(name = "profile_image_url", nullable = true)
    private String profileImageUrl;

    public String getProfileImageUrl() {
        return profileImageUrl;
    }

    public void setProfileImageUrl(String profileImageUrl) {
        this.profileImageUrl = profileImageUrl;
    }

    public boolean isTrainer() {
        return trainer;
    }

    public void setTrainer(boolean trainer) {
        this.trainer = trainer;
    }

    @Override
    public boolean isAdmin() {
        return admin;
    }

    public void setAdmin(boolean admin) {
        this.admin = admin;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }

    

}package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass;

import jakarta.persistence.*;
import java.time.LocalDateTime;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;

@Entity
@Table(name = "group_classes")
public class GroupClass {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String className; // Ej: Zumba, Spinning, etc.

    @Column(nullable = false)
    private LocalDateTime startTime;

    @Column(nullable = false)
    private LocalDateTime endTime;

    @Column(nullable = false)
    private int maxParticipants;

    // Entrenador asignado (opcional, solo si hay uno asignado)
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = true)
    private PersonalTrainer assignedTrainer;

    // Getter y Setters...
    
    public Long getId() {return id;}
    public void setId(Long id){this.id = id;}
    public String getClassName(){return className;}
    public void setClassName(String className){this.className = className;}
    public LocalDateTime getStartTime(){return startTime;}
    public void setStartTime(LocalDateTime startTime){this.startTime = startTime;}
    public LocalDateTime getEndTime(){return endTime;}
    public void setEndTime(LocalDateTime endTime){this.endTime = endTime;}
    public int getMaxParticipants(){return maxParticipants;}
    public void setMaxParticipants(int maxParticipants){this.maxParticipants = maxParticipants;}
    public PersonalTrainer getAssignedTrainer(){return assignedTrainer;}
    public void setAssignedTrainer(PersonalTrainer assignedTrainer){this.assignedTrainer = assignedTrainer;}
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass;

import jakarta.persistence.*;
import java.time.LocalDateTime;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

@Entity
@Table(name = "group_class_bookings",
       uniqueConstraints = {@UniqueConstraint(columnNames = {"user_id","group_class_id"})})
public class GroupClassBooking {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Usuario que reserva la clase
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Clase grupal a la que se reserva
    @ManyToOne
    @JoinColumn(name = "group_class_id", nullable = false)
    private GroupClass groupClass;

    @Column(nullable = false)
    private LocalDateTime bookingTime;

    public Long getId(){return id;}
    public void setId(Long id){this.id = id;}
    public User getUser(){return user;}
    public void setUser(User user){this.user = user;}
    public GroupClass getGroupClass(){return groupClass;}
    public void setGroupClass(GroupClass groupClass){this.groupClass = groupClass;}
    public LocalDateTime getBookingTime(){return bookingTime;}
    public void setBookingTime(LocalDateTime bookingTime){this.bookingTime = bookingTime;}
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.request;

import java.time.LocalDateTime;

public class CreateGroupClassRequest {
    private String className;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private int maxParticipants;
    private Long trainerId; // Nuevo campo opcional

    public Long getTrainerId() {
        return trainerId;
    }
    public void setTrainerId(Long trainerId) {
        this.trainerId = trainerId;
    }
    // Getters y setters
    public String getClassName() {
        return className;
    }
    public void setClassName(String className) {
        this.className = className;
    }
    public LocalDateTime getStartTime() {
        return startTime;
    }
    public void setStartTime(LocalDateTime startTime) {
        this.startTime = startTime;
    }
    public LocalDateTime getEndTime() {
        return endTime;
    }
    public void setEndTime(LocalDateTime endTime) {
        this.endTime = endTime;
    }
    public int getMaxParticipants() {
        return maxParticipants;
    }
    public void setMaxParticipants(int maxParticipants) {
        this.maxParticipants = maxParticipants;
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.models.request;



import com.sebastian.backend.gymapp.backend_gestorgympro.models.IUser;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public class UserRequest implements IUser {
    
    @NotBlank
    @Size(min = 4, max = 8)
    private String username;

    @NotEmpty
    @Email
    private String email;

    @NotBlank
    private String password;

    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    private boolean admin;
    private boolean trainer; 

    @Override
    public boolean isTrainer() {
        return trainer;
    }
    public void setTrainer(boolean trainer) {
        this.trainer = trainer;
    }
    @Override
    public boolean isAdmin() {
        return admin;
    }
    public void setAdmin(boolean admin) {
        this.admin = admin;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }

    
}

package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface BodyMeasurementRepository extends JpaRepository<BodyMeasurement, Long> {
    List<BodyMeasurement> findByClientId(Long clientId); // Para obtener mediciones de un cliente específico
}
package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Booking;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public interface BookingRepository extends JpaRepository<Booking, Long> {
    List<Booking> findByTrainerIdAndStartDateTimeBetween(Long trainerId, LocalDateTime start, LocalDateTime end);

    @Query("SELECT COUNT(b) > 0 FROM Booking b WHERE b.trainer.id = :trainerId AND b.startDateTime = :slotStart")
    boolean existsByTrainerIdAndSlotStart(@Param("trainerId") Long trainerId, @Param("slotStart") LocalDateTime slotStart);
    
      /**
     * Verifica si existe alguna reserva de entrenamiento personal para el entrenador con ID dado,
     * que se solape con el rango [startTime, endTime].
     * Esta consulta asume que cada booking tiene startDateTime y endDateTime.
     */
    @Query("SELECT COUNT(b) > 0 FROM Booking b " +
           "WHERE b.trainer.id = :trainerId " +
           "AND ((b.startDateTime < :endTime AND b.endDateTime > :startTime))")
    boolean hasOverlappingBookings(Long trainerId, LocalDateTime startTime, LocalDateTime endTime);

    List<Booking> findByTrainerId(Long trainerId);

       @Query("SELECT COUNT(b) > 0 FROM Booking b WHERE b.user.id = :userId AND b.trainer.id = :trainerId AND DATE(b.startDateTime) = :slotDate")
    boolean existsByUserIdAndTrainerIdAndSlotDate(@Param("userId") Long userId,
                                                  @Param("trainerId") Long trainerId,
                                                  @Param("slotDate") LocalDate slotDate);

    // Contar reservas durante la semana
    @Query("SELECT COUNT(b) FROM Booking b WHERE b.user.id = :userId AND b.trainer.id = :trainerId AND DATE(b.startDateTime) BETWEEN :startOfWeek AND :endOfWeek")
    long countByUserIdAndTrainerIdAndSlotDateBetween(@Param("userId") Long userId,
                                                     @Param("trainerId") Long trainerId,
                                                     @Param("startOfWeek") LocalDate startOfWeek,
                                                     @Param("endOfWeek") LocalDate endOfWeek);

                                                     List<Booking> findByUserIdAndTrainerIdAndStartDateTimeBetween(Long userId, Long trainerId, LocalDateTime start, LocalDateTime end);

                                                     List<Booking> findByUserId(Long userId);

                                                     @Query("SELECT b FROM Booking b WHERE b.user.id = :userId " +
                                                     "AND b.startDateTime <= :endDate AND b.trainer.id = :trainerId")
                                              List<Booking> findActiveBookingsWithinSubscription(@Param("userId") Long userId,
                                                                                                 @Param("trainerId") Long trainerId,
                                                                                                 @Param("endDate") LocalDateTime endDate);
                                              

}
package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.CarouselImage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CarouselImageRepository extends JpaRepository<CarouselImage, Long> {
    List<CarouselImage> findAllByOrderByOrderNumberAsc();
}
package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;

public interface CategoryRepository extends JpaRepository<Category, Long> {
    Optional<Category> findByName(String name);
    boolean existsByName(String name);
}
package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClassBooking;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;



public interface GroupClassBookingRepository extends JpaRepository<GroupClassBooking, Long> {

    @Query("SELECT COUNT(b) FROM GroupClassBooking b WHERE b.groupClass.id = :classId")
    long countByGroupClassId(@Param("classId") Long classId);

    boolean existsByUserIdAndGroupClassId(Long userId, Long groupClassId);

  


}

package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;

import java.time.LocalDateTime;
import java.util.List;

    public interface GroupClassRepository extends JpaRepository<GroupClass, Long> {
        List<GroupClass> findByStartTimeAfter(LocalDateTime now);

    @Query("SELECT gc FROM GroupClass gc WHERE gc.assignedTrainer.id = :trainerId")
    List<GroupClass> findByAssignedTrainerId(@Param("trainerId") Long trainerId);


    }
package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;

public interface PaymentRepository extends JpaRepository<Payment, Long> {
        List<Payment> findByUserId(Long userId);

        Optional<Payment> findByMercadoPagoId(String mercadoPagoId);

        Optional<Payment> findByExternalReference(String externalReference);

        @Query("SELECT COALESCE(SUM(p.transactionAmount), 0) FROM Payment p")
        BigDecimal getTotalRevenue();

                /**
         * Calcula la suma total de los pagos filtrados por tipo de servicio.
         *
         * @param serviceType El tipo de servicio para filtrar los pagos.
         * @return La suma total de los pagos filtrados como BigDecimal.
         */


        @Query("SELECT SUM(p.transactionAmount) FROM Payment p WHERE p.plan.name = :planType")
        BigDecimal getRevenueByPlanType(@Param("planType") String planType);



        @Query("SELECT COALESCE(SUM(p.transactionAmount), 0) " +
        "FROM Payment p " +
        "WHERE p.planIncluded = :planIncluded AND p.trainerIncluded = :trainerIncluded")
        BigDecimal getRevenueByIncludedFlags(@Param("planIncluded") boolean planIncluded, 
                                        @Param("trainerIncluded") boolean trainerIncluded);

                                        @Query("SELECT p.plan.name AS planName, COALESCE(SUM(p.transactionAmount), 0) AS total " +
                                        "FROM Payment p " +
                                        "WHERE p.plan IS NOT NULL AND p.status = 'approved' " +
                                        "GROUP BY p.plan.name")
                                 List<Object[]> getRevenueGroupedByPlanName();
                                 
         List<Payment> findByUserIdAndStatus(Long userId, String status);                                
}


package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PersonalTrainerRepository extends JpaRepository<PersonalTrainer, Long> {

    boolean existsByUserId(Long userId);

    List<PersonalTrainer> findByAvailability(Boolean availability);

    Optional<PersonalTrainer> findByUserId(Long userId); 

   
}






package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;

public interface PersonalTrainerSubscriptionRepository extends JpaRepository<PersonalTrainerSubscription, Long> {
    List<PersonalTrainerSubscription> findByUserId(Long userId);
    Optional<PersonalTrainerSubscription> findByPaymentId(Long paymentId);
    
}

package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;

public interface PlanRepository extends JpaRepository<Plan, Long> {
    // Métodos personalizados si es necesario
}

package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;


public interface ProductRepository extends JpaRepository<Product, Long> {

    Page<Product> findByCategory(Category category, Pageable pageable); 

    List<Product> findByNameContainingIgnoreCase(String name);


}

package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Role;


public interface RoleRepository 
    extends CrudRepository<Role, Long> {

        Optional<Role> findByName(String username);

    }

package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import java.util.List;
import java.util.Optional;

public interface SubscriptionRepository extends JpaRepository<Subscription, Long> {
    List<Subscription> findByUserId(Long userId);
    List<Subscription> findByPlanId(Long planId);
    Optional<Subscription> findByPaymentId(Long id);
}
package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerAvailability;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;

public interface TrainerAvailabilityRepository extends JpaRepository<TrainerAvailability, Long> {

    List<TrainerAvailability> findByTrainerId(Long trainerId);

    @Query("SELECT t FROM TrainerAvailability t WHERE t.trainer.id = :trainerId AND t.day BETWEEN :startDay AND :endDay")
    List<TrainerAvailability> findByTrainerIdAndDayBetween(@Param("trainerId") Long trainerId,
                                                           @Param("startDay") LocalDate startDay,
                                                           @Param("endDay") LocalDate endDay);

                                                           @Query("SELECT COUNT(t) > 0 FROM TrainerAvailability t WHERE t.trainer.id = :trainerId AND t.day = :day AND t.startTime <= :endTime AND t.endTime >= :startTime")
boolean isTrainerAvailable(@Param("trainerId") Long trainerId,
                           @Param("day") LocalDate day,
                           @Param("startTime") LocalTime startTime,
                           @Param("endTime") LocalTime endTime);
}
package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface TrainerClientRepository extends JpaRepository<TrainerClient, Long> {

    List<TrainerClient> findByTrainerId(Long trainerId);

    List<TrainerClient> findByClientId(Long clientId);

    boolean existsByTrainerIdAndClientId(Long trainerId, Long clientId);
}
package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.Optional;


import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

public interface UserRepository 
    extends CrudRepository<User, Long> {

        Page<User> findAll(Pageable pageable);

        Optional<User> findByUsername(String username);

        Optional<User> getUserByEmail(String email);


        @Query("select u from User u where u.username=?1")
        Optional<User> getUserByUsername(String username);


        boolean existsByEmail(String email);

        boolean existsByUsername(String username);
        
        Page<User> findByUsernameContainingIgnoreCase(String username, Pageable pageable);

        Optional<User> findByEmail(String email);
    }

package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.util.List;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;

public interface CategoryService {
    Category createCategory(String name);
    Category getCategoryByName(String name);
    List<Category> getAllCategories();
    Category updateCategory(Long id, String newName);
    void deleteCategory(Long id);
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.cloudinary.Cloudinary;
import com.cloudinary.Transformation;
import com.cloudinary.utils.ObjectUtils;

import io.github.cdimascio.dotenv.Dotenv;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.util.Map;

@Service
public class CloudinaryService {

    private final Cloudinary cloudinary;

    public CloudinaryService() {
        Dotenv dotenv = Dotenv.load();
        String cloudinaryUrl = dotenv.get("CLOUDINARY_URL");
        cloudinary = new Cloudinary(cloudinaryUrl);
    }

    public String uploadImage(MultipartFile file) throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> params = ObjectUtils.asMap(
            "use_filename", true,
            "unique_filename", false,
            "overwrite", true
        );
    
        @SuppressWarnings("unchecked")
        Map<String, Object> uploadResult = cloudinary.uploader().upload(file.getBytes(), params);
        return (String) uploadResult.get("secure_url");
    }
    

    public Map<String, Object> getImageDetails(String publicId) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> params = ObjectUtils.asMap(
            "quality_analysis", true
        );
    
        @SuppressWarnings("unchecked")
        Map<String, Object> resourceDetails = cloudinary.api().resource(publicId, params);
        return resourceDetails;
    }
    

    public String getTransformedImageUrl(String publicId) {
        return cloudinary.url()
            .transformation(new Transformation()
                .crop("pad")
                .width(300)
                .height(400)
                .background("auto:predominant"))
            .generate(publicId);
    }

    public void deleteImage(String publicId) throws IOException {
        cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendEmail(String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        message.setFrom("smoralespincheira@gmail.com");
    
        mailSender.send(message);
        System.out.println("Correo enviado a: " + to + " | Asunto: " + subject);
    }
    
}

package com.sebastian.backend.gymapp.backend_gestorgympro.services;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClassBooking;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassBookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.impl.SubscriptionServiceImpl;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class GroupClassBookingService {

    @Autowired
    private GroupClassRepository groupClassRepository;

    @Autowired
    private GroupClassBookingRepository groupClassBookingRepository;

    @Autowired
    private SubscriptionServiceImpl subscriptionService;

    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    /**
     * Lógica de reserva:
     * - El cliente debe tener un plan activo (gimnasio o gimnasio+entrenador)
     * - Puede reservar desde 12 horas antes hasta 1 hora antes de la clase
     * - Verificar que no haya alcanzado el cupo máximo
     * - Verificar que la clase no haya comenzado
     * - Verificar que el usuario no haya reservado ya esa clase
     */
    @Transactional
    public boolean bookClass(User user, Long classId) {
        GroupClass gc = groupClassRepository.findById(classId)
            .orElseThrow(() -> new IllegalArgumentException("Clase no encontrada"));

        LocalDateTime now = LocalDateTime.now();

        // Verificar que tenga algún plan activo
        // Para simplificar, asumamos que si el usuario tiene cualquier suscripción activa (plan o entrenador), puede reservar
        boolean hasActivePlan = subscriptionService.hasAnyActiveSubscription(user.getId()) ||
                                !personalTrainerSubscriptionService.getSubscriptionsByUserId(user.getId()).isEmpty();

        System.out.println("plan activo"+hasActivePlan);

        if(!hasActivePlan) {
            throw new IllegalArgumentException("No tienes plan activo para reservar esta clase");
        }

        // Verificar ventana de tiempo: desde 12h antes hasta 1h antes
        LocalDateTime classStart = gc.getStartTime();
   

      

        // Verificar que no haya comenzado la clase
        if (now.isAfter(classStart)) {
            throw new IllegalArgumentException("La clase ya ha comenzado, no puedes reservar");
        }

        // Verificar cupo
        long currentBookings = groupClassBookingRepository.countByGroupClassId(classId);
        if (currentBookings >= gc.getMaxParticipants()) {
            throw new IllegalArgumentException("La clase ya alcanzó el cupo máximo");
        }

        // Verificar que el usuario no haya reservado ya esta clase
        if (groupClassBookingRepository.existsByUserIdAndGroupClassId(user.getId(), classId)) {
            throw new IllegalArgumentException("Ya tienes una reserva en esta clase");
        }
        

        // Crear reserva
        GroupClassBooking booking = new GroupClassBooking();
        booking.setUser(user);
        booking.setGroupClass(gc);
        booking.setBookingTime(now);
        groupClassBookingRepository.save(booking);

        return true;
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.GroupClassDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassBookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerAvailabilityRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class GroupClassService {

    @Autowired
    private GroupClassRepository groupClassRepository;

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

        @Autowired
    private BookingRepository bookingRepository;

    @Autowired
    private GroupClassBookingRepository GroupbookingRepository;

    @Autowired
    private TrainerAvailabilityRepository trainerAvailabilityRepository;

    

    /**
     * Crea una nueva clase grupal sin asignar entrenador todavía.
     */

    @Transactional
    public GroupClass createGroupClass(String className, LocalDateTime startTime, LocalDateTime endTime, int maxParticipants) {
        GroupClass gc = new GroupClass();
        gc.setClassName(className);
        gc.setStartTime(startTime);
        gc.setEndTime(endTime);
        gc.setMaxParticipants(maxParticipants);
        return groupClassRepository.save(gc);
    }

    /**
     * Asigna un entrenador a la clase grupal, verificando su disponibilidad.
     */

    @Transactional
    public void assignTrainerToClass(Long classId, Long trainerId) {
        GroupClass gc = groupClassRepository.findById(classId)
            .orElseThrow(() -> new IllegalArgumentException("Clase no encontrada"));
    
        PersonalTrainer trainer = personalTrainerRepository.findById(trainerId)
            .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado"));
    
        // Verificar disponibilidad del entrenador en ese horario:
        boolean hasOverlap = bookingRepository.hasOverlappingBookings(trainerId, gc.getStartTime(), gc.getEndTime());
        boolean isAvailableForClass = trainerAvailabilityRepository.isTrainerAvailable(
            trainerId,
            gc.getStartTime().toLocalDate(),
            gc.getStartTime().toLocalTime(),
            gc.getEndTime().toLocalTime()
        );
    
        if (hasOverlap || !isAvailableForClass) {
            throw new IllegalArgumentException("El entrenador no está disponible en el horario de esta clase");
        }
    
        gc.setAssignedTrainer(trainer);
        groupClassRepository.save(gc);
    }

    public Optional<GroupClass> findById(Long id){
        return groupClassRepository.findById(id);
    }

    public List<GroupClassDto> findFutureClasses() {
        List<GroupClass> futureClasses = groupClassRepository.findByStartTimeAfter(LocalDateTime.now());
        
        return futureClasses.stream()
            .map(gc -> {
                long currentBookings = GroupbookingRepository.countByGroupClassId(gc.getId());
                return new GroupClassDto(gc, currentBookings);
            })
            .toList();
    }
    

     public GroupClassDto getClassDetails(Long classId) {
        GroupClass groupClass = groupClassRepository.findById(classId)
            .orElseThrow(() -> new IllegalArgumentException("Clase no encontrada"));

        long currentBookings = GroupbookingRepository.countByGroupClassId(classId);
        return new GroupClassDto(groupClass, currentBookings);
    }

    public GroupClass save(GroupClass groupClass) {
        return groupClassRepository.save(groupClass);
    }

}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service("jpaUserDetailsService")
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        System.out.println("JpaUserDetailsService: Cargando usuario por email: " + email);
        Optional<com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User> o = repository
                .getUserByEmail(email); // Cambia a un método que busque por correo

        if (!o.isPresent()) {
            System.out.println("JpaUserDetailsService: Usuario no encontrado con email: " + email);
            throw new UsernameNotFoundException(String.format("Email %s no existe en el sistema!", email));
        }

        com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User user = o.orElseThrow();
        List<GrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(r -> new SimpleGrantedAuthority(r.getName()))
                .collect(Collectors.toList());

        System.out.println("JpaUserDetailsService: Usuario encontrado: " + email + " con roles: " + authorities);

        return new User(
                user.getEmail(), // Cambia para usar el correo
                user.getPassword(),
                true, true, true, true,
                authorities);
    }

}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.mercadoPago.MercadoPagoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class PaymentCreationService {

    @Autowired
    private MercadoPagoService mercadoPagoService;

    @Autowired
    private PaymentService paymentService;

    // Inyectamos las URLs desde application.properties
    @Value("${mercadopago.successUrl}")
    private String successUrl;

    @Value("${mercadopago.failureUrl}")
    private String failureUrl;

    @Value("${mercadopago.pendingUrl}")
    private String pendingUrl;

    public Preference createPayment(Payment payment, String description) throws MPException {
        System.out.println("=== Creando pago ===");
        System.out.println("Usuario: " + (payment.getUser() != null ? payment.getUser().getEmail() : "NULO"));
        System.out.println("Monto: " + payment.getTransactionAmount());
        System.out.println("Estado: " + payment.getStatus());

        // Validar que el usuario no sea nulo
        if (payment.getUser() == null) {
            throw new IllegalArgumentException("El usuario no puede ser nulo en el pago.");
        }

        // Guardar el pago inicial (pendiente)
        paymentService.savePayment(payment);

        // Verificar si el ID es nulo después de guardar
        if (payment.getId() == null) {
            throw new IllegalStateException("El ID del pago es nulo después de guardarlo.");
        }

        // Generar referencia externa
        String externalReference = payment.getId().toString();
        payment.setExternalReference(externalReference);
        paymentService.savePayment(payment);

        // Crear preferencia en Mercado Pago
        return mercadoPagoService.createPreference(
                description,
                1,
                payment.getTransactionAmount(),
                successUrl,
                failureUrl,
                pendingUrl,
                payment.getUser().getEmail(),
                externalReference
        );
    }
}

package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mercadopago.client.payment.PaymentClient;
import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;

@Service
public class PaymentNotificationService {

    @Autowired
    private PaymentService paymentService;
    @Autowired
    private EmailService emailService;
    @Autowired
    private SubscriptionService subscriptionService;
    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;
    @Autowired
    private TrainerService trainerService;

    public void processNotification(Map<String, String> params) throws MPException, MPApiException {
        System.out.println("Notificación recibida: " + params);

        String topic = params.get("topic");
        String type = params.get("type");
        String id = params.get("id");
        String dataId = params.get("data.id");

        // Validar que sea pago
        if ("payment".equals(topic) || "payment".equals(type)) {
            if (id == null) {
                id = dataId;
            }
            System.out.println("ID del pago a procesar: " + id);

            PaymentClient paymentClient = new PaymentClient();
            com.mercadopago.resources.payment.Payment mpPayment = paymentClient.get(Long.parseLong(id));
            System.out.println("Detalle del pago desde MP: " + mpPayment);

            String externalReference = mpPayment.getExternalReference();
            Optional<Payment> optPayment = paymentService.getPaymentByExternalReference(externalReference);

            if (optPayment.isPresent()) {
                Payment dbPayment = optPayment.get();
                System.out.println("Payment en DB: " + dbPayment);

                // Actualizar estado
                dbPayment.setStatus(mpPayment.getStatus().toString());
                if (mpPayment.getDateApproved() != null) {
                    dbPayment.setPaymentDate(mpPayment.getDateApproved().toLocalDateTime());
                }
                dbPayment.setMercadoPagoId(mpPayment.getId().toString());
                dbPayment.setUpdateDate(LocalDateTime.now());
                paymentService.savePayment(dbPayment);

                // Si está aprobado => manejar suscripciones y correo
                if ("approved".equals(mpPayment.getStatus().toString())) {
                    System.out.println("El pago está aprobado. Procesando suscripciones...");
                    String destinatario = dbPayment.getUser().getEmail();
                    String asunto = "Confirmación de Pago";
                    String cuerpo = "Hola " + dbPayment.getUser().getUsername() + ", tu pago se ha realizado con éxito.";
                    emailService.sendEmail(destinatario, asunto, cuerpo);

                    if (dbPayment.isPlanIncluded()) {
                        handlePlanSubscription(dbPayment);
                    }
                    if (dbPayment.isTrainerIncluded()) {
                        handleTrainerSubscription(dbPayment);
                    }
                }

            } else {
                System.out.println("Payment no encontrado en la DB para reference: " + externalReference);
            }
        } else {
            System.out.println("Notificación no es de tipo 'payment'. Ignorando.");
        }
    }

    private void handlePlanSubscription(Payment dbPayment) {
        // Crear la suscripción del plan
        Subscription subscription = subscriptionService.createSubscriptionForPayment(dbPayment);
        System.out.println("Suscripción creada: " + subscription);

        // Manejar entrenadores incluidos en el plan
        List<PersonalTrainer> includedTrainers = subscription.getPlan().getIncludedTrainers();
        if (includedTrainers != null) {
            for (PersonalTrainer trainer : includedTrainers) {
                personalTrainerSubscriptionService.createSubscriptionForTrainerOnly(dbPayment, trainer);
                Long trainerId = trainer.getId();
                Long clientUserId = dbPayment.getUser().getId();
                trainerService.addClientToTrainer(trainerId, clientUserId);
                System.out.println("Cliente asignado al entrenador " + trainerId);
            }
        }
    }

    private void handleTrainerSubscription(Payment dbPayment) {
        Long trainerId = dbPayment.getTrainerId();
        PersonalTrainer trainer = trainerService.findPersonalTrainerById(trainerId)
            .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));
        System.out.println("Entrenador encontrado para suscripción: " + trainer);

        personalTrainerSubscriptionService.createSubscriptionForTrainerOnly(dbPayment, trainer);
        Long clientUserId = dbPayment.getUser().getId();
        trainerService.addClientToTrainer(trainerId, clientUserId);
        System.out.println("Cliente asignado al entrenador (Trainer ID: " + trainerId +
                           ", Client ID: " + clientUserId + ")");
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

@Service
public class PaymentReportService {

    @Autowired
    private PaymentService paymentService;
    @Autowired
    private UserService userService;

    public List<PaymentDTO> getMyPayments(String userEmail) {
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
        return paymentService.getPaymentsByUserId(user.getId());
    }

    public BigDecimal getTotalRevenue() {
        return paymentService.getTotalRevenue();
    }

    public Map<String, Object> getAdminDashboardRevenue() {
        return paymentService.getAdminDashboardRevenue();
    }
}

package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PaymentRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.SubscriptionRepository;

@Service
public class PaymentService {

    @Autowired
    private PaymentRepository paymentRepository;

    @Autowired
    private SubscriptionRepository subscriptionRepository;

    @Autowired
    private EmailService emailService;

    public Payment savePayment(Payment payment) {
        Payment savedPayment = paymentRepository.save(payment);

        if ("approved".equals(payment.getStatus())) {
            sendPurchaseConfirmationEmail(payment);
        }

        return savedPayment;
    }

   public List<PaymentDTO> getPaymentsByUserId(Long userId) {
    List<Payment> payments = paymentRepository.findByUserIdAndStatus(userId, "approved");  // Filtrar desde BD
    return payments.stream().map(payment -> {
        PaymentDTO dto = new PaymentDTO();
        dto.setId(payment.getId());
        dto.setPlanName(payment.getPlan() != null ? payment.getPlan().getName() : "Sin Plan");
        dto.setPaymentDate(payment.getPaymentDate());
        dto.setPaymentMethod(payment.getPaymentMethod());
        dto.setTransactionAmount(payment.getTransactionAmount());
        
        Optional<Subscription> subscriptionOpt = subscriptionRepository.findByPaymentId(payment.getId());
        subscriptionOpt.ifPresent(subscription -> {
            dto.setSubscriptionStartDate(subscription.getStartDate());
            dto.setSubscriptionEndDate(subscription.getEndDate());
        });

        return dto;
    }).collect(Collectors.toList());
}

    

    public Optional<Payment> getPaymentByMercadoPagoId(String mercadoPagoId) {
        return paymentRepository.findByMercadoPagoId(mercadoPagoId);
    }

    public Optional<Payment> getPaymentByExternalReference(String externalReference) {
        return paymentRepository.findByExternalReference(externalReference);
    }

    public BigDecimal getRevenueByPlanType(String planType) {
        System.out.println("Parámetro planType recibido: " + planType);
        BigDecimal result = paymentRepository.getRevenueByPlanType(planType);
        return result != null ? result : BigDecimal.ZERO;
    }
    
    

    
    /**
         * Obtiene la suma total de todos los pagos registrados.
         *
         * @return La suma total de los pagos como BigDecimal.
         */
        public BigDecimal getTotalRevenue() {
            return paymentRepository.getTotalRevenue();
        }

     
  /*  
    public BigDecimal getTotalRevenueByServiceType(Payment.serviceType serviceType) {
        System.out.println("Parámetro serviceType recibido: " + serviceType);
        return paymentRepository.getTotalRevenueByServiceType(serviceType);
    }
    

    public boolean existsByServiceType(Payment.serviceType serviceType) {
        return paymentRepository.existsByServiceType(serviceType);
    }
 */
    public BigDecimal getRevenueByIncludedFlags(boolean planIncluded, boolean trainerIncluded) {
        return paymentRepository.getRevenueByIncludedFlags(planIncluded, trainerIncluded);
    }

     public Map<String, Object> getAdminDashboardRevenue() {
        Map<String, Object> dashboardRevenue = new HashMap<>();

        // 1. Ingresos por servicios
        Map<String, BigDecimal> serviceRevenue = new HashMap<>();
        serviceRevenue.put("personalTrainer", paymentRepository.getRevenueByIncludedFlags(false, true));
        serviceRevenue.put("planAndTrainer", paymentRepository.getRevenueByIncludedFlags(true, true));
        serviceRevenue.put("plan", paymentRepository.getRevenueByIncludedFlags(true, false));

        dashboardRevenue.put("serviceRevenue", serviceRevenue);

        // 2. Ingresos dinámicos por planes
        Map<String, BigDecimal> planRevenue = new HashMap<>();
        List<Object[]> revenueByPlan = paymentRepository.getRevenueGroupedByPlanName();
        for (Object[] row : revenueByPlan) {
            String planName = (String) row[0];
            BigDecimal total = (BigDecimal) row[1];
            planRevenue.put(planName, total);
        }

        dashboardRevenue.put("planRevenue", planRevenue);

        return dashboardRevenue;
    }

 

    private void sendPurchaseConfirmationEmail(Payment payment) {
        String email = payment.getUser().getEmail();
        String subject = "Confirmación de Compra - GymPro";
        String body = "Hola " + payment.getUser().getUsername() + ",\n\n" +
                      "Gracias por tu compra. El total fue: $" + payment.getTransactionAmount() + "\n" +
                      "Detalles:\n" +
                      (payment.getPlan() != null ? "Plan: " + payment.getPlan().getName() + "\n" : "") +
                      (payment.getTrainerId() != null ? "Entrenador: " + payment.getTrainerId() + "\n" : "") +
                      "Estado: " + payment.getStatus() + "\n\n" +
                      "¡Gracias por confiar en nosotros!";
        
        emailService.sendEmail(email, subject, body);
    }
    
    
}

// PersonalTrainerSubscriptionService.java
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.util.List;
import java.util.Optional;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;

public interface PersonalTrainerSubscriptionService {

    void createSubscriptionForTrainerOnly(Payment payment, PersonalTrainer trainer);

    List<PersonalTrainerSubscription> getSubscriptionsByUserId(Long userId);
    
    boolean hasActiveTrainerSubscription(Long userId, Long trainerId);

    Optional<PersonalTrainerSubscription> findActiveSubscriptionForUser(Long userId);
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PlanRepository;

@Service
public class PlanService {

    @Autowired
    private PlanRepository planRepository;

    public List<Plan> getAllPlans() {
        return planRepository.findAll();
    }

    public Plan getPlanById(Long id) {
        return planRepository.findById(id).orElse(null);
    }

    public Plan createPlan(Plan plan) {
        return planRepository.save(plan);
    }

    public Plan updatePlan(Long id, Plan planDetails) {
        Plan plan = planRepository.findById(id).orElse(null);
        if (plan != null) {
            plan.setName(planDetails.getName());
            plan.setPrice(planDetails.getPrice());
            return planRepository.save(plan);
        }
        return null;
    }

    public void deletePlan(Long id) {
        planRepository.deleteById(id);
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;

@Service
public class PlanTrainerPaymentService {

    @Autowired
    private UserService userService;

    @Autowired
    private PlanService planService;

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    @Autowired
    private PaymentCreationService paymentCreationService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private PaymentService paymentService;

    /**
     * Crea un pago y la preferencia de Mercado Pago para:
     *   - Solo Plan
     *   - Solo Entrenador
     *   - Plan + Entrenador
     *
     * Reproduce la misma lógica que estaba en createPlanPaymentPreference:
     *  - (onlyTrainer && planId != null) => excepción
     *  - Si planId != null => busca plan, suma precio
     *  - Si trainerId != null => busca entrenador, suma tarifa
     *  - Si no se selecciona nada => excepción
     *  - Crea Payment y Preference
     *  - Envío de correo.
     *
     * @param userEmail   Email del usuario autenticado
     * @param planId      ID del plan (puede ser null)
     * @param trainerId   ID del entrenador (puede ser null)
     * @param onlyTrainer Flag que indica "solo entrenador"
     * @return Preference de Mercado Pago
     * @throws MPException si ocurre error con MercadoPago
     */
    public Preference createPlanTrainerPayment(String userEmail,
    Long planId,
    Long trainerId,
    boolean onlyTrainer) throws MPException {
        User user = getUserOrThrow(userEmail);
        validatePlanTrainerCombination(onlyTrainer, planId);
        Plan plan = retrievePlanIfPresent(planId);
        PersonalTrainer trainer = retrieveTrainerIfPresent(trainerId);
        BigDecimal totalPrice = calculateTotalPrice(plan, trainer);
        Payment payment = buildPayment(user, plan, trainer, totalPrice);
        Preference preference = createPreferenceInMercadoPago(payment);
        sendConfirmationEmail(user, plan, trainer, totalPrice);
        return preference;

        
    }
    private User getUserOrThrow(String userEmail) {
        return userService.findByEmail(userEmail)
            .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
    }
    
    private void validatePlanTrainerCombination(boolean onlyTrainer, Long planId) {
        if (onlyTrainer && planId != null) {
            throw new IllegalArgumentException("No se puede comprar solo entrenador si se selecciona un plan.");
        }
    }
    
    private Plan retrievePlanIfPresent(Long planId) {
        if (planId == null) return null;
        Plan plan = planService.getPlanById(planId);
        if (plan == null) {
            throw new IllegalArgumentException("Plan no encontrado con ID: " + planId);
        }
        return plan;
    }
    
    private PersonalTrainer retrieveTrainerIfPresent(Long trainerId) {
        if (trainerId == null) return null;
        PersonalTrainer trainer = personalTrainerRepository.findById(trainerId)
            .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));
        if (!trainer.getAvailability()) {
            throw new IllegalArgumentException("El entrenador no está disponible.");
        }
        if (trainer.getMonthlyFee() == null) {
            throw new IllegalArgumentException("El entrenador no tiene una tarifa definida.");
        }
        return trainer;
    }
    
    private BigDecimal calculateTotalPrice(Plan plan, PersonalTrainer trainer) {
        BigDecimal total = BigDecimal.ZERO;
        if (plan != null) {
            total = total.add(plan.getPrice());
        }
        if (trainer != null) {
            total = total.add(trainer.getMonthlyFee());
        }
        if (total.compareTo(BigDecimal.ZERO) == 0) {
            throw new IllegalArgumentException("Debe seleccionar al menos un plan o un entrenador.");
        }
        return total;
    }
    
    private Payment buildPayment(User user, Plan plan, PersonalTrainer trainer, BigDecimal totalPrice) {
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setPlan(plan);
        payment.setTrainerId(trainer != null ? trainer.getId() : null);
        payment.setStatus("pending");
        payment.setTransactionAmount(totalPrice);
        payment.setTrainerIncluded(trainer != null);
        payment.setPlanIncluded(plan != null);
        return payment;
    }
    
    private Preference createPreferenceInMercadoPago(Payment payment) throws MPException {
        return paymentCreationService.createPayment(payment, "Compra de Plan/Entrenador");
    }
    
    private void sendConfirmationEmail(User user, Plan plan, PersonalTrainer trainer, BigDecimal totalPrice) {
        String emailBody = buildEmailBody(user, plan, trainer, totalPrice);
        emailService.sendEmail(user.getEmail(), "Confirmación de compra - GestorGymPro", emailBody);
    }
    

    /**
     * Construye el cuerpo del correo de confirmación
     * con toda la información de plan y/o entrenador.
     */
    private String buildEmailBody(User user, Plan plan, PersonalTrainer trainer, BigDecimal totalPrice) {
        StringBuilder sb = new StringBuilder();
        sb.append("Hola ").append(user.getUsername()).append(",\n\n")
          .append("Tu compra de ");
        
        if (plan != null) {
            sb.append("el plan '").append(plan.getName()).append("' ");
        }
        if (trainer != null) {
            sb.append(plan != null ? "y el entrenador " : "el entrenador ")
              .append(trainer.getUser().getUsername()).append(" ");
        }
        sb.append("se ha registrado con éxito.\n\n")
          .append("Monto total: $").append(totalPrice).append("\n")
          .append("Gracias por tu compra.");

        return sb.toString();
    }
}

package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.mercadoPago.MercadoPagoService;

@Service
public class ProductPaymentService {

    @Autowired
    private UserService userService;
    @Autowired
    private PaymentService paymentService;
    @Autowired
    private PaymentCreationService paymentCreationService;

    public Preference createProductPayment(String userEmail, List<Map<String, Object>> items) throws MPException {
        // 1. Buscar usuario
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        // 2. Calcular precio total
        BigDecimal totalPrice = BigDecimal.ZERO;
        for (Map<String, Object> item : items) {
            BigDecimal unitPrice = new BigDecimal(item.get("unitPrice").toString());
            int quantity = Integer.parseInt(item.get("quantity").toString());
            totalPrice = totalPrice.add(unitPrice.multiply(BigDecimal.valueOf(quantity)));
        }

        // 3. Crear Payment en DB
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setTransactionAmount(totalPrice);
        payment.setStatus("pending");
        payment.setPlanIncluded(false);
        payment.setTrainerIncluded(false);

        paymentService.savePayment(payment);

        // 4. Crear preferencia
        return paymentCreationService.createPayment(payment, "Compra de Productos");
    }

    public Preference createSingleProductPayment(String userEmail, Long productId, Integer quantity, 
                                                 ProductService productService,
                                                 String successUrl, String failureUrl, String pendingUrl,
                                                 MercadoPagoService mercadoPagoService) throws MPException {
        // 1. User
        User user = userService.findByEmail(userEmail)
            .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        // 2. Producto
        Product product = productService.getProductById(productId); // lanza excepción si no existe
        BigDecimal unitPrice = product.getPrice();
        BigDecimal totalPrice = unitPrice.multiply(BigDecimal.valueOf(quantity));

        // 3. Payment
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setStatus("pending");
        payment.setTransactionAmount(totalPrice);
        payment.setPaymentMethod("Mercado Pago");
        paymentService.savePayment(payment);

        // 4. Generar externalReference
        String externalReference = payment.getId().toString();
        payment.setExternalReference(externalReference);
        paymentService.savePayment(payment);

        // 5. Crear preferencia
        return mercadoPagoService.createPreference(
            product.getName(),
            quantity,
            unitPrice,
            successUrl,
            failureUrl,
            pendingUrl,
            user.getEmail(),
            externalReference
        );
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;

public interface ProductService {
    Product createProduct(Product product);
    List<Product> getAllProducts();
    Product getProductById(Long id);
    Product updateProduct(Long id, Product product);
    void deleteProduct(Long id);
    List<Product> getProductsByCategory(Category category);

    Page<Product> findByCategory(Category category, Pageable pageable);
    Page<Product> findAll(Pageable pageable);
    List<Product> searchProducts(String term);


}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;

import org.springframework.web.multipart.MultipartFile;

public interface ProfileService {


    UserDto updateProfile(UserRequest userRequest, MultipartFile file, String currentEmail);
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.util.List;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;

public interface SubscriptionService {
    
    /**
     * Crea una nueva suscripción.
     *
     * @param subscription La suscripción a crear.
     * @return La suscripción creada.
     */
    Subscription createSubscription(Subscription subscription);

    /**
     * Obtiene todas las suscripciones de un usuario por su ID.
     *
     * @param userId El ID del usuario.
     * @return Lista de suscripciones del usuario.
     */
    List<Subscription> getSubscriptionsByUserId(Long userId);

    /**
     * Crea una suscripción a partir de un pago.
     *
     * @param payment El pago asociado a la suscripción.
     * @return La suscripción creada.
     */
    Subscription createSubscriptionForPayment(Payment payment);
    
    /**
     * Verifica si el usuario tiene una suscripción activa que incluye al entrenador especificado.
     *
     * @param userId     ID del usuario.
     * @param trainerId  ID del entrenador.
     * @return true si tiene una suscripción activa con el entrenador, false en caso contrario.
     */
    boolean hasActivePlanWithTrainer(Long userId, Long trainerId);

    boolean hasAnyActiveSubscription(Long userId);
}   
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TimeSlotDTO;

import java.time.LocalDateTime;
import java.util.List;

public interface TrainerScheduleService {
    List<TimeSlotDTO> getWeeklySlotsForTrainer(Long trainerId);
    boolean bookSlot(Long userId, Long trainerId, LocalDateTime slotStart);
    List<CalendarEventDTO> getTrainerCalendar(Long trainerId);
    List<CalendarEventDTO> getClientSessions(Long clientId);
}

package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ActiveClientInfoDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.BodyMeasurementDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerUpdateRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Routine;

public interface TrainerService {

    void assignTrainerRole(Long userId, String specialization, Integer experienceYears, Boolean availability, 
                       BigDecimal monthlyFee, String title, String studies, String certifications, String description);

    void updateTrainerDetails(String email, TrainerUpdateRequest request);


    void addClientToTrainer(Long trainerId, Long clientId);

    void removeClientFromTrainer(Long trainerId, Long clientId);

       void addBodyMeasurement(Long trainerId, Long clientId, BodyMeasurementDto measurementDto);


    void addRoutine(Long trainerId, Long clientId, Routine routine);

    List<BodyMeasurement> getClientBodyMeasurements(Long clientId);

    List<Routine> getClientRoutines(Long clientId);

    List<UserDto> getAssignedClients(Long trainerId);

    List<PersonalTrainerDto> getAvailableTrainers();

    Optional<PersonalTrainer> findByUserId(Long userId);

    // En TrainerService
Optional<PersonalTrainer> findPersonalTrainerById(Long trainerId);

    /**
     * Retorna la lista de clientes que tienen un plan o sub personal con este entrenador,
     * con la información de las fechas de suscripción.
     */
    List<ActiveClientInfoDTO> getActiveClientsInfoForTrainer(Long personalTrainerId);

    List<PersonalTrainerDto> getAvailableTrainersForSlot(LocalDate day, LocalTime startTime, LocalTime endTime);

}

package com.sebastian.backend.gymapp.backend_gestorgympro.services;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;

import java.util.List;
import java.util.Optional;


import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;


public interface UserService {

        List<UserDto> findAll();

        Optional<User> findByEmail(String email);

        boolean existsByEmail(String email);
        
        boolean existsByUsername(String username);

        Page<UserDto> findAll(Pageable pageable);

        Page<UserDto> findByUsernameContaining(String search, Pageable pageable);

        Optional<UserDto> findById(Long id);

        UserDto save(User user);

         Optional<UserDto> update(UserRequest user, Long id);

        void remove(Long id);

        

       

}
package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.CategoryRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CategoryService;

@Service
public class CategoryServiceImpl implements CategoryService {

    private final CategoryRepository categoryRepository;

    public CategoryServiceImpl(CategoryRepository categoryRepository) {
        this.categoryRepository = categoryRepository;
    }

    @Override
    public Category createCategory(String name) {
        // Verificar si la categoría existe
        categoryRepository.findByName(name).ifPresent(c -> {
            throw new IllegalArgumentException("La categoría ya existe");
        });
        Category category = new Category();
        category.setName(name);
        return categoryRepository.save(category);
    }

    @Override
    public Category getCategoryByName(String name) {
        return categoryRepository.findByName(name)
                .orElseThrow(() -> new IllegalArgumentException("Categoría no encontrada: " + name));
    }

    @Override
    public List<Category> getAllCategories() {
        return categoryRepository.findAll();
    }

    @Override
    public Category updateCategory(Long id, String newName) {
        Category category = categoryRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Categoría no encontrada con ID: " + id));
        category.setName(newName);
        return categoryRepository.save(category);
    }

    @Override
    public void deleteCategory(Long id) {
        Category category = categoryRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Categoría no encontrada con ID: " + id));
        categoryRepository.delete(category);
    }
}


package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerSubscriptionRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Service
public class PersonalTrainerSubscriptionServiceImpl implements PersonalTrainerSubscriptionService {

    @Autowired
    private PersonalTrainerSubscriptionRepository personalTrainerSubscriptionRepository;

        @Autowired
    private PersonalTrainerRepository personalTrainerRepository; // Inyectamos el repositorio



    @Override
    public boolean hasActiveTrainerSubscription(Long userId, Long trainerId) {
        List<PersonalTrainerSubscription> subscriptions = personalTrainerSubscriptionRepository.findByUserId(userId);
        return subscriptions.stream().anyMatch(sub -> 
            sub.getPersonalTrainer().getId().equals(trainerId) && sub.getActive()
        );
    }

    @Override
    @Transactional
    public void createSubscriptionForTrainerOnly(Payment payment, PersonalTrainer trainer) {
        // Crear la suscripción para el entrenador
        PersonalTrainerSubscription subscription = new PersonalTrainerSubscription();
        subscription.setUser(payment.getUser());
        subscription.setPersonalTrainer(trainer);
        subscription.setPayment(payment);
        subscription.setStartDate(LocalDate.now());
        subscription.setEndDate(LocalDate.now().plusMonths(1)); // Duración estándar de 1 mes (ejemplo)
        subscription.setActive(true);

        personalTrainerSubscriptionRepository.save(subscription);
    }

@Override
public List<PersonalTrainerSubscription> getSubscriptionsByUserId(Long userId) {
    return personalTrainerSubscriptionRepository.findByUserId(userId);
}

@Override
public Optional<PersonalTrainerSubscription> findActiveSubscriptionForUser(Long userId) {
    List<PersonalTrainerSubscription> subscriptions = personalTrainerSubscriptionRepository.findByUserId(userId);
    return subscriptions.stream()
            .filter(PersonalTrainerSubscription::getActive)
            .findFirst();
}

}
package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.ProductRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProductService;
import org.springframework.stereotype.Service;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import java.util.List;

@Service
public class ProductServiceImpl implements ProductService {
    
    private final ProductRepository productRepository;

    public ProductServiceImpl(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @Override
    public Product createProduct(Product product) {
        return productRepository.save(product);
    }

    @Override
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    @Override
    public Product getProductById(Long id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Producto no encontrado con ID: " + id));
    }

    @Override
    public Product updateProduct(Long id, Product productDetails) {
        Product product = getProductById(id);
        product.setName(productDetails.getName());
        product.setDescription(productDetails.getDescription());
        product.setPrice(productDetails.getPrice());
        product.setCategory(productDetails.getCategory());
        product.setImageUrl(productDetails.getImageUrl());
        return productRepository.save(product);
    }

    @Override
    public void deleteProduct(Long id) {
        Product product = getProductById(id);
        productRepository.delete(product);
    }

    @Override
    public List<Product> getProductsByCategory(Category category) {
        return productRepository.findByCategory(category);
    }

    @Override
    public Page<Product> findByCategory(Category category, Pageable pageable) {
        return productRepository.findByCategory(category, pageable);
    }

    @Override
    public Page<Product> findAll(Pageable pageable) {
        return productRepository.findAll(pageable);
    }

        @Override
    public List<Product> searchProducts(String term) {
        // Ejemplo sencillo usando un método finder en el repositorio
        return productRepository.findByNameContainingIgnoreCase(term);
    }


}
package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear.DtoMapperUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CloudinaryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProfileService;


import java.io.IOException;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
public class ProfileServiceImpl implements ProfileService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CloudinaryService cloudinaryService;

    @Autowired
    private PasswordEncoder passwordEncoder;



    @Override
    public UserDto updateProfile(UserRequest userRequest, MultipartFile file, String currentEmail) {
        Optional<User> optionalUser = userRepository.findByEmail(currentEmail);
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Usuario no encontrado");
        }

        User user = optionalUser.get();

        if (userRequest.getUsername() != null) user.setUsername(userRequest.getUsername());
        if (userRequest.getEmail() != null) user.setEmail(userRequest.getEmail());
        if (userRequest.getPassword() != null && !userRequest.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        }

        if (file != null && !file.isEmpty()) {
            try {
                String imageUrl = cloudinaryService.uploadImage(file);
                user.setProfileImageUrl(imageUrl);
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException("Error al subir la imagen de perfil");
            }
        }

        userRepository.save(user);
        return DtoMapperUser.builder().setUser(user).build();
    }
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDate;
import java.util.List;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.SubscriptionRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.SubscriptionService;

@Service
public class SubscriptionServiceImpl implements SubscriptionService{

    @Autowired
    private SubscriptionRepository subscriptionRepository;

    public Subscription createSubscription(Subscription subscription) {
        return subscriptionRepository.save(subscription);
    }

    public List<Subscription> getSubscriptionsByUserId(Long userId) {
        return subscriptionRepository.findByUserId(userId);
    }

    @Override
    @Transactional
    public Subscription createSubscriptionForPayment(Payment payment) {
        Subscription subscription = new Subscription();
        subscription.setUser(payment.getUser());
        subscription.setPlan(payment.getPlan());
        subscription.setStartDate(LocalDate.now());
        subscription.setEndDate(LocalDate.now().plusYears(1)); // Por ejemplo, un año
        subscription.setActive(true);
        subscription.setPayment(payment); // Establecer el pago asociado
        return subscriptionRepository.save(subscription);
    }

    
    @Override
    public boolean hasActivePlanWithTrainer(Long userId, Long trainerId) {
        System.out.println("Verificando suscripciones activas para el usuario " + userId + " con el entrenador " + trainerId);
    
        List<Subscription> activeSubscriptions = subscriptionRepository.findByUserId(userId).stream()
                .filter(Subscription::getActive)
                .toList();
    
        System.out.println("Suscripciones activas encontradas: " + activeSubscriptions);
    
        for (Subscription sub : activeSubscriptions) {
            Plan plan = sub.getPlan();
            if (plan != null && plan.getIncludedTrainers() != null) {
                for (PersonalTrainer trainer : plan.getIncludedTrainers()) {
                    System.out.println("Entrenador en el plan: " + trainer.getId());
                    if (trainer.getId().equals(trainerId)) {
                        System.out.println("Suscripción válida encontrada.");
                        return true;
                    }
                }
            }
        }
        System.out.println("No se encontraron suscripciones válidas.");
        return false;
    }
    
    @Override
public boolean hasAnyActiveSubscription(Long userId) {
    List<Subscription> subscriptions = subscriptionRepository.findByUserId(userId);
    // Verificar si existe al menos una suscripción activa
    return subscriptions.stream().anyMatch(Subscription::getActive);
}



}
package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TimeSlotDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerAvailability;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Booking;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerAvailabilityRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class TrainerScheduleServiceImpl implements TrainerScheduleService {

    @Autowired
    private TrainerAvailabilityRepository trainerAvailabilityRepository;

    @Autowired
    private BookingRepository bookingRepository;

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    @Autowired
    private UserRepository userRepository;


    @Autowired
    private GroupClassRepository groupClassRepository;

    @Autowired
    private  PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

   @Override
@Transactional(readOnly = true)
public List<TimeSlotDTO> getWeeklySlotsForTrainer(Long trainerId) {
    LocalDate today = LocalDate.now();
    LocalDate monday = today.with(DayOfWeek.MONDAY);
    LocalDate sunday = monday.plusWeeks(2);  // Extiende a dos semanas


    System.out.println("Calculando slots para el entrenador: " + trainerId);
    System.out.println("Rango de fechas: " + monday + " a " + sunday);

    List<TrainerAvailability> availabilities = trainerAvailabilityRepository.findByTrainerIdAndDayBetween(trainerId, monday, sunday);
    System.out.println("Disponibilidades encontradas en la base de datos: " + availabilities);

    List<TimeSlotDTO> slots = new ArrayList<>();

    for (TrainerAvailability availability : availabilities) {
        LocalDate date = availability.getDay();
        LocalTime startTime = availability.getStartTime();
        LocalTime endTime = availability.getEndTime();
        System.out.println("Procesando disponibilidad: " + date + " " + startTime + " - " + endTime);

        LocalTime slotStart = startTime;
        while (slotStart.plusHours(1).isBefore(endTime) || slotStart.plusHours(1).equals(endTime)) {
            LocalTime slotEnd = slotStart.plusHours(1);
            LocalDateTime start = LocalDateTime.of(date, slotStart);
            LocalDateTime end = LocalDateTime.of(date, slotEnd);

            boolean booked = bookingRepository.existsByTrainerIdAndSlotStart(trainerId, start);
            System.out.println("Slot generado: " + start + " - " + end + ", reservado: " + booked);

            TimeSlotDTO dto = new TimeSlotDTO();
            dto.setTrainerId(trainerId);
            dto.setStartDateTime(start);
            dto.setEndDateTime(end);
            dto.setAvailable(!booked);
            slots.add(dto);

            slotStart = slotEnd;
        }
    }

    System.out.println("Total de slots generados: " + slots.size());
    return slots;
}

        @Override
        @Transactional
        public boolean bookSlot(Long userId, Long trainerId, LocalDateTime slotStart) {
            // Verificar que el entrenador existe
            PersonalTrainer trainer = personalTrainerRepository.findById(trainerId)
                    .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado"));

            // Verificar que el usuario existe
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

            LocalDate slotDate = slotStart.toLocalDate();

            // Validar si ya tiene una reserva el mismo día
            boolean alreadyBookedToday = bookingRepository.existsByUserIdAndTrainerIdAndSlotDate(userId, trainerId, slotDate);
            if (alreadyBookedToday) {
                throw new IllegalStateException("Ya tienes una reserva con este entrenador para el mismo día.");
            }

            // Validar si tiene más de 5 reservas en la misma semana
            LocalDate startOfWeek = slotDate.with(DayOfWeek.MONDAY);
            LocalDate endOfWeek = startOfWeek.plusDays(6);
            long weeklyBookings = bookingRepository.countByUserIdAndTrainerIdAndSlotDateBetween(userId, trainerId, startOfWeek, endOfWeek);
            if (weeklyBookings >= 5) {
                throw new IllegalStateException("Has alcanzado el límite de 5 reservas semanales con este entrenador.");
            }

            // Verificar si ya está reservado ese slot
            boolean booked = bookingRepository.existsByTrainerIdAndSlotStart(trainerId, slotStart);
            if (booked) {
                throw new IllegalStateException("Este horario ya ha sido reservado por otro usuario.");
            }

            // Proceder con la reserva
            Booking booking = new Booking();
            booking.setUser(user);
            booking.setTrainer(trainer);
            booking.setStartDateTime(slotStart);
            booking.setEndDateTime(slotStart.plusHours(1)); 

            bookingRepository.save(booking);
            return true;
        }



      @Transactional(readOnly = true)
    public List<CalendarEventDTO> getTrainerCalendar(Long trainerId) {
        // 1. Obtener bookings (entrenos personales) para ese trainer
        List<Booking> personalBookings = bookingRepository.findByTrainerId(trainerId);

        // 2. Convertirlos a CalendarEventDTO
        List<CalendarEventDTO> personalEvents = personalBookings.stream()
            .map(b -> {
                CalendarEventDTO dto = new CalendarEventDTO();
                dto.setId(b.getId());
                // El "title" puede ser algo como "Sesión con <nombre del cliente>"
                dto.setTitle("Entreno con " + b.getUser().getUsername());
                dto.setStart(b.getStartDateTime());
                dto.setEnd(b.getEndDateTime());
                dto.setEventType("PERSONAL");
                return dto;
            })
            .collect(Collectors.toList());

        // 3. Obtener las clases grupales donde assignedTrainer = trainerId
        List<GroupClass> groupClasses = groupClassRepository.findByAssignedTrainerId(trainerId);

        // 4. Convertirlas a CalendarEventDTO
        List<CalendarEventDTO> groupEvents = groupClasses.stream()
            .map(gc -> {
                CalendarEventDTO dto = new CalendarEventDTO();
                dto.setId(gc.getId());
                dto.setTitle("Clase: " + gc.getClassName());
                dto.setStart(gc.getStartTime());
                dto.setEnd(gc.getEndTime());
                dto.setEventType("GROUP");
                return dto;
            })
            .collect(Collectors.toList());

        // 5. Unir ambas listas
        List<CalendarEventDTO> allEvents = new ArrayList<>();
        allEvents.addAll(personalEvents);
        allEvents.addAll(groupEvents);

        return allEvents;
    }

  
   @Override
@Transactional(readOnly = true)
public List<CalendarEventDTO> getClientSessions(Long clientId) {
    List<Booking> bookings = bookingRepository.findByUserId(clientId);
    List<CalendarEventDTO> futureSessions = new ArrayList<>();

    for (Booking booking : bookings) {
        LocalDateTime start = booking.getStartDateTime();
        LocalDateTime end = booking.getEndDateTime();

        // Obtener la fecha de fin de suscripción
        Optional<PersonalTrainerSubscription> activeSub = personalTrainerSubscriptionService
                .findActiveSubscriptionForUser(clientId);

        if (activeSub.isPresent()) {
            LocalDate endDate = activeSub.get().getEndDate();

            // Repetir semanalmente hasta la fecha de fin de suscripción
            while (start.toLocalDate().isBefore(endDate)) {
                CalendarEventDTO dto = new CalendarEventDTO();
                dto.setId(booking.getId());
                dto.setTitle("Sesión con " + booking.getTrainer().getUser().getUsername());
                dto.setStart(start);
                dto.setEnd(end);
                dto.setEventType("PERSONAL");
                futureSessions.add(dto);

                // Incrementar 1 semana para la próxima sesión
                start = start.plusWeeks(1);
                end = end.plusWeeks(1);
            }
        }
    }

    return futureSessions;
}

    

    
}
package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ActiveClientInfoDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.BodyMeasurementDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerUpdateRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear.DtoMapperUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Role;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerClient;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BodyMeasurementRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.RoleRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerAvailabilityRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerClientRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.SubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;

import jakarta.persistence.EntityNotFoundException;

@Service
public class TrainerServiceImpl implements TrainerService{
   @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    @Autowired
    private TrainerClientRepository trainerClientRepository;

    // Agrega estas líneas para inyectar los servicios faltantes
    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Autowired
    private SubscriptionService subscriptionService;

    @Autowired
    private BodyMeasurementRepository bodyMeasurementRepository;

    @Autowired
    private BookingRepository bookingRepository;


    @Autowired
    private TrainerAvailabilityRepository trainerAvailabilityRepository;

@Transactional
public void assignTrainerRole(Long userId, String specialization, Integer experienceYears, Boolean availability, BigDecimal monthlyFee, String title, String studies, String certifications, String description) {
    Optional<User> userOptional = userRepository.findById(userId);
    if (userOptional.isEmpty()) {
        throw new EntityNotFoundException("Usuario no encontrado con ID: " + userId);
    }

    User user = userOptional.get();

    // Verificar si el rol de ROLE_TRAINER existe
    Role trainerRole = roleRepository.findByName("ROLE_TRAINER")
            .orElseThrow(() -> new EntityNotFoundException("Rol 'ROLE_TRAINER' no encontrado"));

    // Asignar el rol si no lo tiene
    if (!user.getRoles().contains(trainerRole)) {
        user.getRoles().add(trainerRole);
    }

    // Verificar si ya existe un registro de PersonalTrainer
    if (personalTrainerRepository.existsByUserId(userId)) {
        throw new IllegalArgumentException("Este usuario ya está registrado como personal trainer.");
    }

    PersonalTrainer personalTrainer = new PersonalTrainer();
    personalTrainer.setUser(user);
    personalTrainer.setSpecialization(specialization);
    personalTrainer.setExperienceYears(experienceYears);
    personalTrainer.setAvailability(availability);
    personalTrainer.setMonthlyFee(monthlyFee);

    // Asignar los nuevos campos
    personalTrainer.setTitle(title);
    personalTrainer.setStudies(studies);
    personalTrainer.setCertifications(certifications);
    personalTrainer.setDescription(description);

    personalTrainerRepository.save(personalTrainer);
    userRepository.save(user);
}

        



        @Override
        @Transactional
        public void addClientToTrainer(Long trainerId, Long clientId) {
            // Recuperar el PersonalTrainer por su ID
            PersonalTrainer trainer = personalTrainerRepository.findById(trainerId)
                .orElseThrow(() -> new EntityNotFoundException("Entrenador no encontrado con ID: " + trainerId));
        
            // Recuperar el cliente por su ID
            User client = userRepository.findById(clientId)
                .orElseThrow(() -> new EntityNotFoundException("Cliente no encontrado con ID: " + clientId));
        
            // Verificar que el entrenador tiene el rol 'ROLE_TRAINER'
            boolean isTrainer = trainer.getUser().getRoles().stream()
                    .anyMatch(role -> role.getName().equals("ROLE_TRAINER"));
        
            if (!isTrainer) {
                throw new IllegalArgumentException("El usuario no es un entrenador");
            }
        
            // Verificar si ya existe la relación
            if (trainerClientRepository.existsByTrainerIdAndClientId(trainerId, clientId)) {
                throw new IllegalArgumentException("El cliente ya está asignado a este entrenador");
            }
        
            // Crear y guardar la relación
            TrainerClient trainerClient = new TrainerClient();
            trainerClient.setTrainer(trainer); // Ahora 'trainer' es un PersonalTrainer
            trainerClient.setClient(client);
        
            trainerClientRepository.save(trainerClient);
        }
        
        
        

    @Override
    @Transactional
    public void removeClientFromTrainer(Long trainerId, Long clientId) {
        // Implementación del método
    }
/* 
        @Override
    @Transactional(readOnly = true)
    public List<UserDto> getAssignedClients(Long trainerId) {
        List<TrainerClient> trainerClients = trainerClientRepository.findByTrainerId(trainerId);
        List<UserDto> clients = trainerClients.stream()
                .map(tc -> DtoMapperUser.builder().setUser(tc.getClient()).build())
                .collect(Collectors.toList());
        return clients;
    }
*/
@Override
@Transactional(readOnly = true)
public List<UserDto> getAssignedClients(Long trainerId) {
    List<TrainerClient> trainerClients = trainerClientRepository.findByTrainerId(trainerId);
    List<UserDto> clients = trainerClients.stream()
        .map(tc -> DtoMapperUser.builder().setUser(tc.getClient()).build())
        .filter(clientDto -> {
            Long clientId = clientDto.getId();
            // Verificar si el cliente tiene suscripción activa con este entrenador
            boolean hasTrainerOnly = personalTrainerSubscriptionService.hasActiveTrainerSubscription(clientId, trainerId);
            // Verificar si el cliente tiene un plan activo que incluya al entrenador
            boolean hasPlanWithTrainer = subscriptionService.hasActivePlanWithTrainer(clientId, trainerId);
            return hasTrainerOnly || hasPlanWithTrainer;
        })
        .collect(Collectors.toList());
    return clients;
}



    @Override
    @Transactional(readOnly = true)
    public List<PersonalTrainerDto> getAvailableTrainers() {
        List<PersonalTrainer> trainers = personalTrainerRepository.findByAvailability(true);
        return trainers.stream()
            .map(trainer -> {
                User user = trainer.getUser();
                return new PersonalTrainerDto(
                    trainer.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    trainer.getSpecialization(),
                    trainer.getExperienceYears(),
                    trainer.getAvailability(),
                    user.getProfileImageUrl(),
                    trainer.getTitle(),
                    trainer.getStudies(),
                    trainer.getCertifications(),
                    trainer.getDescription()
                );
            })
            .collect(Collectors.toList());
    }

    @Override
@Transactional
public void updateTrainerDetails(String email, TrainerUpdateRequest request) {
    User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

    // Verificar si existe un registro de PersonalTrainer para este usuario
    PersonalTrainer pt = personalTrainerRepository.findByUserId(user.getId())
        .orElseThrow(() -> new IllegalArgumentException("Este usuario no está registrado como entrenador"));

    // Actualizar campos del entrenador
    if (request.getTitle() != null) pt.setTitle(request.getTitle());
    if (request.getStudies() != null) pt.setStudies(request.getStudies());
    if (request.getCertifications() != null) pt.setCertifications(request.getCertifications());
    if (request.getDescription() != null) pt.setDescription(request.getDescription());
    if (request.getMonthlyFee() != null) pt.setMonthlyFee(request.getMonthlyFee());

    personalTrainerRepository.save(pt);
}

@Override
public Optional<PersonalTrainer> findByUserId(Long userId) {
    return personalTrainerRepository.findByUserId(userId);
}

@Override
@Transactional(readOnly = true)
public Optional<PersonalTrainer> findPersonalTrainerById(Long trainerId) {
    return personalTrainerRepository.findById(trainerId);
}

@Override
@Transactional
public void addBodyMeasurement(Long trainerId, Long clientId, BodyMeasurementDto measurementDto) {
    User client = userRepository.findById(clientId)
        .orElseThrow(() -> new EntityNotFoundException("Cliente no encontrado"));
    User trainer = userRepository.findById(trainerId)
        .orElseThrow(() -> new EntityNotFoundException("Entrenador no encontrado"));

    BodyMeasurement measurement = new BodyMeasurement();
    measurement.setClient(client);
    measurement.setTrainer(trainer);

  
    measurement.setClientName(measurementDto.getClientName());

    measurement.setAge(measurementDto.getAge());
    measurement.setWeight(measurementDto.getWeight());
    measurement.setHeight(measurementDto.getHeight());
    measurement.setBodyFatPercentage(measurementDto.getBodyFatPercentage());
    measurement.setDate(measurementDto.getDate());

    measurement.setInjuries(measurementDto.getInjuries());
    measurement.setMedications(measurementDto.getMedications());
    measurement.setOtherHealthInfo(measurementDto.getOtherHealthInfo());

    measurement.setCurrentlyExercising(measurementDto.getCurrentlyExercising());
    measurement.setSportsPracticed(measurementDto.getSportsPracticed());

    measurement.setCurrentWeight(measurementDto.getCurrentWeight());
    measurement.setBmi(measurementDto.getBmi());

    measurement.setRelaxedArm(measurementDto.getRelaxedArm());
    measurement.setWaist(measurementDto.getWaist());
    measurement.setMidThigh(measurementDto.getMidThigh());
    measurement.setFlexedArm(measurementDto.getFlexedArm());
    measurement.setHips(measurementDto.getHips());
    measurement.setCalf(measurementDto.getCalf());

    measurement.setTricepFold(measurementDto.getTricepFold());
    measurement.setSubscapularFold(measurementDto.getSubscapularFold());
    measurement.setBicepFold(measurementDto.getBicepFold());
    measurement.setSuprailiacFold(measurementDto.getSuprailiacFold());

    measurement.setSumOfFolds(measurementDto.getSumOfFolds());
    measurement.setPercentageOfFolds(measurementDto.getPercentageOfFolds());
    measurement.setFatMass(measurementDto.getFatMass());
    measurement.setLeanMass(measurementDto.getLeanMass());
    measurement.setMuscleMass(measurementDto.getMuscleMass());

    measurement.setIdealMinWeight(measurementDto.getIdealMinWeight());
    measurement.setIdealMaxWeight(measurementDto.getIdealMaxWeight());
    measurement.setTrainerRecommendations(measurementDto.getTrainerRecommendations());

    bodyMeasurementRepository.save(measurement);
}


@Override
@Transactional(readOnly = true)
public List<BodyMeasurement> getClientBodyMeasurements(Long clientId) {
    return bodyMeasurementRepository.findByClientId(clientId);
}

@Override
@Transactional(readOnly = true)
public List<ActiveClientInfoDTO> getActiveClientsInfoForTrainer(Long personalTrainerId) {
    // 1. Listar los TrainerClient de este entrenador
    List<TrainerClient> trainerClients = trainerClientRepository.findByTrainerId(personalTrainerId);

    // 2. Para cada cliente, revisamos:
    //    - Si tiene un plan activo (en la tabla subscriptions)
    //    - Si tiene una suscripción de entrenador personal (tabla personal_trainer_subscriptions) con este entrenador
    return trainerClients.stream().map(tc -> {
        User client = tc.getClient();

        ActiveClientInfoDTO dto = new ActiveClientInfoDTO();
        dto.setClientId(client.getId());
        dto.setClientName(client.getUsername());
        dto.setClientEmail(client.getEmail());

        // (A) Revisar si el cliente tiene ALGÚN plan activo (sin importar el entrenador)
        List<Subscription> subs = subscriptionService.getSubscriptionsByUserId(client.getId());
        // Basta con encontrar la primera suscripción activa
        Optional<Subscription> planSub = subs.stream()
            .filter(Subscription::getActive)
            .findFirst();

        // Si existe plan activo, llenamos planName y planStart/End
        planSub.ifPresent(s -> {
            dto.setPlanName(s.getPlan().getName());
            dto.setPlanStart(s.getStartDate());
            dto.setPlanEnd(s.getEndDate());
        });

        // (B) Revisar la suscripción personal con ESTE entrenador
        List<PersonalTrainerSubscription> ptSubs =
            personalTrainerSubscriptionService.getSubscriptionsByUserId(client.getId());

        Optional<PersonalTrainerSubscription> personalSub = ptSubs.stream()
            .filter(pts -> pts.getActive() != null && pts.getActive())
            .filter(pts -> pts.getPersonalTrainer().getId().equals(personalTrainerId))
            .findFirst();

        personalSub.ifPresent(pts -> {
            dto.setTrainerStart(pts.getStartDate());
            dto.setTrainerEnd(pts.getEndDate());
        });

        return dto;
    })
    // Filtramos: sólo mostrar si tiene plan o tiene sub de entrenador
    .filter(dto -> dto.getPlanName() != null || dto.getTrainerStart() != null)
    .collect(Collectors.toList());
}
    // src/main/java/com/sebastian/backend/gymapp/backend_gestorgympro/services/impl/TrainerServiceImpl.java

@Override
@Transactional(readOnly = true)
public List<PersonalTrainerDto> getAvailableTrainersForSlot(LocalDate day, LocalTime startTime, LocalTime endTime) {
    // Convertir a LocalDateTime
    LocalDateTime startDateTime = LocalDateTime.of(day, startTime);
    LocalDateTime endDateTime = LocalDateTime.of(day, endTime);

    // Obtener entrenadores que estén disponibles y no tengan reservas en ese rango
    List<PersonalTrainer> allAvailableTrainers = personalTrainerRepository.findByAvailability(true);

    // Filtrar entrenadores que no tienen reservas que se solapen con el rango de tiempo
    List<PersonalTrainer> availableTrainers = allAvailableTrainers.stream()
            .filter(trainer -> {
                boolean hasOverlap = bookingRepository.hasOverlappingBookings(trainer.getId(), startDateTime, endDateTime);
                boolean isAvailableForClass = trainerAvailabilityRepository.isTrainerAvailable(trainer.getId(), day, startTime, endTime);
                return !hasOverlap && isAvailableForClass;
            })
            .collect(Collectors.toList());

    // Convertir a DTO
    return availableTrainers.stream()
            .map(trainer -> {
                User user = trainer.getUser();
                return new PersonalTrainerDto(
                        trainer.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        trainer.getSpecialization(),
                        trainer.getExperienceYears(),
                        trainer.getAvailability(),
                        user.getProfileImageUrl(),
                        trainer.getTitle(),
                        trainer.getStudies(),
                        trainer.getCertifications(),
                        trainer.getDescription()
                );
            })
            .collect(Collectors.toList());
}


}
package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.IUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear.DtoMapperUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Role;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.RoleRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CloudinaryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;

import jakarta.persistence.EntityNotFoundException;

import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;


    @Service
    public class UserServiceImpl implements UserService{

        @Autowired
        private UserRepository repository;

        
        @Autowired
        private CloudinaryService cloudinaryService;

        @Autowired
        private RoleRepository roleRepository;

        @Autowired
        private PersonalTrainerRepository personalTrainerRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;;

        @Override
        @Transactional(readOnly = true)
        public List<UserDto> findAll() {
            List<User> users = (List<User>) repository.findAll();
            return users
                .stream()
                .map(u -> DtoMapperUser.builder().setUser(u).build())
                .collect(Collectors.toList());
        }

/* 
        @Override
        @Transactional(readOnly = true)
        public Optional<UserDto> findById(Long id) {
            Optional<User> o = repository.findById(id);
            if (o.isPresent()) {
                return Optional.of(
                    DtoMapperUser
                        .builder()
                        .setUser(o.orElseThrow())
                        .build()
                );
            }
            return Optional.empty();
        }
*/


        @Override
        @Transactional(readOnly = true)
        public Page<UserDto> findAll(Pageable pageable) {
            Page<User> usersPage = repository.findAll(pageable);
            return usersPage.map(u -> DtoMapperUser.builder().setUser(u).build());
        }

        @Override
        @Transactional(readOnly = true)
        public Page<UserDto> findByUsernameContaining(String search, Pageable pageable) {
            Page<User> usersPage = repository.findByUsernameContainingIgnoreCase(search, pageable);
            return usersPage.map(u -> DtoMapperUser.builder().setUser(u).build());
        }


        
        @Override
        @Transactional(readOnly = true)
        public Optional<UserDto> findById(Long id) {
            return repository.findById(id).map(u -> DtoMapperUser
                .builder()
                .setUser(u)
                .build());
        }


        @Override
        @Transactional
        public UserDto save(User user) {
  
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        
            List<Role> roles = getRoles(user);
        
            user.setRoles(roles);
        
            return DtoMapperUser.builder().setUser(repository.save(user)).build();
        }
        
        
        

        @Override
        public void remove(Long id) {
            repository.deleteById(id);
        }

        @Override
        @Transactional
        public Optional<UserDto> update(UserRequest user, Long id) {
            Optional<User> o = repository.findById(id);
            User userOptional = null;
            if (o.isPresent()){
                User userDb = o.orElseThrow();
                List<Role> roles = getRoles(user);
                userDb.setRoles(roles);
                userDb.setUsername(user.getUsername());
                userDb.setEmail(user.getEmail());
                userOptional = repository.save(userDb);
            }
            return Optional.ofNullable(DtoMapperUser.builder().setUser(userOptional).build());
        }
        



private List<Role> getRoles(IUser user) {
    
    Optional<Role> ou = roleRepository.findByName("ROLE_USER");

    List<Role> roles = new ArrayList<>();
    if (ou.isPresent()) {
        roles.add(ou.orElseThrow());
    }

    if (user.isAdmin()) {
        Optional<Role> oa = roleRepository.findByName("ROLE_ADMIN");
        if (oa.isPresent()) {
            roles.add(oa.orElseThrow());
        }
    }
    System.out.println("Valor de trainer: " + user.isTrainer());
    if (user.isTrainer()) {
        Optional<Role> ot = roleRepository.findByName("ROLE_TRAINER");
        if (ot.isPresent()) {
            roles.add(ot.orElseThrow());
        }
    }

    return roles;
}

        @Override
        public boolean existsByEmail(String email) {
            return repository.existsByEmail(email);
        }

        @Override
        public boolean existsByUsername(String username) {
            return repository.existsByUsername(username);
}


@Override
@Transactional(readOnly = true)
public Optional<User> findByEmail(String email) {
    return repository.findByEmail(email);
}


        
    }


package com.sebastian.backend.gymapp.backend_gestorgympro.services.mercadoPago;

import com.mercadopago.*;
import com.mercadopago.client.preference.PreferenceClient;
import com.mercadopago.client.preference.PreferenceItemRequest;
import com.mercadopago.client.preference.PreferenceRequest;
import com.mercadopago.client.preference.PreferenceBackUrlsRequest;
import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.preference.Preference;
import com.mercadopago.client.preference.PreferencePayerRequest;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

import java.math.BigDecimal;
import java.util.Arrays;

@Service
public class MercadoPagoService {

    @Value("${mercadopago.accessToken}")
    private String accessToken;

    @PostConstruct
    public void init() throws MPException {
        System.out.println("AQUI ESTA EL ACCES TOKKEN DE MERCADO PAGO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!: " + accessToken);
        MercadoPagoConfig.setAccessToken(accessToken);
    }

    public Preference createPreference(String title, int quantity, BigDecimal unitPrice, String successUrl, String failureUrl, String pendingUrl, String payerEmail, String externalReference) {
        try {
            PreferenceClient client = new PreferenceClient();
    
            PreferenceItemRequest itemRequest = PreferenceItemRequest.builder()
                    .title(title)
                    .quantity(quantity)
                    .unitPrice(unitPrice)
                    .build();
    
            PreferenceBackUrlsRequest backUrls = PreferenceBackUrlsRequest.builder()
                    .success(successUrl)
                    .failure(failureUrl)
                    .pending(pendingUrl)
                    .build();
    
            // Establecer el email del comprador
            PreferencePayerRequest payerRequest = PreferencePayerRequest.builder()
                    .email(payerEmail)
                    .build();
    
            PreferenceRequest preferenceRequest = PreferenceRequest.builder()
                    .items(Arrays.asList(itemRequest))
                    .backUrls(backUrls)
                    .notificationUrl("https://8b2f-2800-150-14e-1f21-ec62-aa60-2ddf-4afe.ngrok-free.app/payment/notifications")
                    .payer(payerRequest)
                    .externalReference(externalReference)
                    .autoReturn("approved")
                    .build();
    
            Preference preference = client.create(preferenceRequest);
            return preference;
        } catch (MPApiException | MPException e) {
            // Maneja la excepción
            System.err.println("Error al crear la preferencia: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

}
