package com.example.demo.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.UserRepository;

/**
 * Test security JWT
 */
public class UserDetailsServiceImplementorTest {
    private final UserRepository userRepo = mock(UserRepository.class);
    private UserDetailServiceImpl userDetailsServiceImpltor;

    @Before
    public void setUp() {
        userDetailsServiceImpltor = new UserDetailServiceImpl(userRepo);
        com.example.demo.TestUtils.injectObjects(userDetailsServiceImpltor, "applicationUserRepository", userRepo);
    }

    /**
     * test for loading user
     */
    @Test
    public void testLoadUserByUsername() {
        String username = "nguyen";
        User user = new User();
        user.setUsername(username);
        String password = "1234";
        user.setPassWord(password);
        user.setId(0L);
        when(userRepo.findByUsername(username)).thenReturn(user);

        UserDetails userDetails = userDetailsServiceImpltor.loadUserByUsername(username);
        assertNotNull(userDetails);
        Collection<? extends GrantedAuthority> authorityCollection = userDetails.getAuthorities();
        assertNotNull(authorityCollection);
        assertEquals(0, authorityCollection.size());
        assertEquals(password, userDetails.getPassword());
        assertEquals(username, userDetails.getUsername());
    }
}
