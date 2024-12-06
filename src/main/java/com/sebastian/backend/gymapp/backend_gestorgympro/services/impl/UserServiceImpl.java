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


