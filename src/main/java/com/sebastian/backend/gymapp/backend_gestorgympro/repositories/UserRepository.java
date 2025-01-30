package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.Optional;


import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

public interface UserRepository 
    extends CrudRepository<User, Long> {

        @Query("SELECT u FROM User u WHERE u.active = true")
        Page<User> findAllActive(Pageable pageable);

        Optional<User> findByUsername(String username);

        Optional<User> getUserByEmail(String email);


        @Query("select u from User u where u.username=?1")
        Optional<User> getUserByUsername(String username);


        boolean existsByEmail(String email);

        boolean existsByUsername(String username);
        
          // Para búsquedas por username (solo activos):
    @Query("""
        SELECT u 
        FROM User u 
        WHERE LOWER(u.username) LIKE LOWER(CONCAT('%', :search, '%')) 
          AND u.active = true
    """)
    Page<User> findByUsernameContainingIgnoreCaseAndActiveTrue(@Param("search") String search, Pageable pageable);

    @Query("""
        SELECT u 
        FROM User u 
        WHERE u.email = :email 
          AND u.active = true
    """)
    Optional<User> findByEmailAndActiveTrue(@Param("email") String email);
    }

