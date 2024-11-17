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

