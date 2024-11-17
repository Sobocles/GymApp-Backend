package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Role;


public interface RoleRepository 
    extends CrudRepository<Role, Long> {

        Optional<Role> findByName(String username);

    }

