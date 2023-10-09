package com.example.demo.security;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.UserRepository;

import lombok.NoArgsConstructor;

@Service
@NoArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    public UserDetailServiceImpl(UserRepository userRepository) {
        super();
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (ObjectUtils.isEmpty(user)) {
            return null;
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassWord(),
                new ArrayList<>());
    }

}
