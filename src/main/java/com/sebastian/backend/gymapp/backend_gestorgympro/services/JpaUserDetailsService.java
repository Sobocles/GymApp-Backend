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

@Service
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User> o = repository
                .getUserByEmail(email); // Cambia a un método que busque por correo
        
        if (!o.isPresent()) {
            throw new UsernameNotFoundException(String.format("Email %s no existe en el sistema!", email));
        }
        
        com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User user = o.orElseThrow();
        List<GrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(r -> new SimpleGrantedAuthority(r.getName()))
                .collect(Collectors.toList());
    
        return new User(
                user.getEmail(), // Cambia para usar el correo
                user.getPassword(),
                true, true, true, true,
                authorities);
    }
    

}