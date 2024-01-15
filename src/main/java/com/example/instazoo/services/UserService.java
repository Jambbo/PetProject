package com.example.instazoo.services;

import com.example.instazoo.dto.UserDTO;
import com.example.instazoo.entity.User;
import com.example.instazoo.entity.enums.ERole;
import com.example.instazoo.exceptions.UserExistsException;
import com.example.instazoo.payload.request.SignupRequest;
import com.example.instazoo.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
public class UserService {
        public static final Logger LOG = LoggerFactory.getLogger(UserService.class);

        private final UserRepository userRepository;
        private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public User createUser(SignupRequest userIn){
            User user = new User();
            user.setEmail(userIn.getEmail());
            user.setName(userIn.getEmail());
            user.setLastname(userIn.getLastname());
            user.setUsername(userIn.getUsername());
            user.setPassword(bCryptPasswordEncoder.encode(userIn.getPassword()));
            user.getRoles().add(ERole.ROLE_USER);

            try{
                LOG.info("Saving User {}",userIn.getEmail());
                return userRepository.save(user);
            }catch(Exception e){
                LOG.error("Error during registration {}",e.getMessage());
                throw new UserExistsException("The user "+ userIn.getUsername()+" already exists. Please check credentials");
            }
    }

    public User update(UserDTO userDTO, Principal principal){
            User user = getUserByPrincipal(principal);
            user.setName(userDTO.getFirstname());
            user.setLastname(userDTO.getLastname());
            user.setBio(userDTO.getBio());
         return userRepository.save(user);
    }

    public User getCurrentUser(Principal principal){
        return getUserByPrincipal(principal);
    }

    private User getUserByPrincipal(Principal principal){
        String username = principal.getName();
        return userRepository.findUserByUsername(username).orElseThrow(
                ()->new UsernameNotFoundException("Username not found with username "+username)
        );
    }
}
