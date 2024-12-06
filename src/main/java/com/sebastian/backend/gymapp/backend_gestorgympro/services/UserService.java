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
