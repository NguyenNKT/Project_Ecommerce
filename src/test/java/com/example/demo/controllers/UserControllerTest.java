package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserControllerTest {
    public static final String USER_NAME = "nguyen";
    
    @Autowired
    private UserController userController;
    
    @Autowired
    private final UserRepository userRepo = mock(UserRepository.class);

    @Autowired
    private final CartRepository cartRepo = mock(CartRepository.class);

    @Autowired
    private final BCryptPasswordEncoder encoder = mock(BCryptPasswordEncoder.class);

    @Before
    public void setUp() {
        userController = new UserController();
        TestUtils.injectObjects(userController, "userRepository", userRepo);
        TestUtils.injectObjects(userController, "cartRepository", cartRepo);
        TestUtils.injectObjects(userController, "bCryptPasswordEncoder", encoder);
    }

    @Test
    public void createUserHappyPath() {
        when(encoder.encode("testPassword")).thenReturn("1234");
        CreateUserRequest r = new CreateUserRequest();
        r.setUsername(USER_NAME);
        r.setPassWord("testPassword");
        r.setConfirmPassWord("testPassword");
        final ResponseEntity<User> response = userController.createUser(r);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        User u = response.getBody();
        assertNotNull(u);
        assertEquals(0, u.getId());
        assertEquals(USER_NAME, u.getUsername());
        assertEquals("1234", u.getPassWord());
    }

    /**
     * Test get User By Id's User
     */
    @Test
    public void findById() {
        when(encoder.encode("testPassword")).thenReturn("1234");
        CreateUserRequest r = new CreateUserRequest();
        r.setUsername(USER_NAME);
        r.setPassWord("testPassword");
        r.setConfirmPassWord("testPassword");
        final ResponseEntity<User> response = userController.createUser(r);
        User user = response.getBody();
        when(userRepo.findById(0L)).thenReturn(java.util.Optional.ofNullable(user));

        final ResponseEntity<User> userResponseEntity = userController.findById(0L);

        User u = userResponseEntity.getBody();
        assertNotNull(u);
        assertEquals(0, u.getId());
        assertEquals(USER_NAME, u.getUsername());
        assertEquals("1234", u.getPassWord());
    }

    /**
     * Test find User By User Name
     */
    @Test
    public void findByUserName() {
        when(encoder.encode("testPassword")).thenReturn("1234");
        CreateUserRequest r = new CreateUserRequest();
        r.setUsername(USER_NAME);
        r.setPassWord("testPassword");
        r.setConfirmPassWord("testPassword");
        final ResponseEntity<User> response = userController.createUser(r);
        User user = response.getBody();
        when(userRepo.findByUsername(USER_NAME)).thenReturn(user);

        final ResponseEntity<User> userResponseEntity = userController.findByUserName(USER_NAME);

        User u = userResponseEntity.getBody();
        assertNotNull(u);
        assertEquals(0, u.getId());
        assertEquals(USER_NAME, u.getUsername());
        assertEquals("1234", u.getPassWord());
    }
}
