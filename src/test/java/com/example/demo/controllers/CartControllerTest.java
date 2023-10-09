package com.example.demo.controllers;

import static org.junit.Assert.assertEquals;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.ItemRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.ModifyCartRequest;

@ExtendWith(MockitoExtension.class)
public class CartControllerTest {

    @InjectMocks
    CartController cartController;

    @Mock
    UserRepository userRepository;

    @Mock
    ItemRepository itemRepository;

    @Mock
    CartRepository cartRepository;

    /**
     * Test function add Cart
     */

    @Test
    void addToCartNotFoundUser() {
        Mockito.doReturn(null).when(userRepository).findByUsername(Mockito.any());
        ResponseEntity<Cart> responseEntity = cartController.addTocart(new ModifyCartRequest());
        assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
    }

    @Test
    void addToCartNotFoundItem() {
        Mockito.doReturn(new User()).when(userRepository).findByUsername(Mockito.any());
        Mockito.doReturn(Optional.empty()).when(itemRepository).findById(Mockito.any());
        ResponseEntity<Cart> responseEntity = cartController.addTocart(new ModifyCartRequest());
        assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
    }

    @Test
    void addToCartSuccess() {
        ModifyCartRequest request = new ModifyCartRequest();
        request.setQuantity(3);

        User user = createUser();
        Cart cart = createCart();
        Item item = createItem();

        List<Item> items = new ArrayList<>();
        items.add(item);
        cart.setUser(user);
        cart.setItems(items);
        user.setCart(cart);

        Mockito.doReturn(user).when(userRepository).findByUsername(Mockito.any());
        Mockito.doReturn(Optional.of(item)).when(itemRepository).findById(Mockito.any());

        ResponseEntity<Cart> responseEntity = cartController.addTocart(request);

        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(cart, responseEntity.getBody());
    }

    @Test
    void removeFromCart_NotFoundUser() {
        Mockito.doReturn(null).when(userRepository).findByUsername(Mockito.any());
        ResponseEntity<Cart> responseEntity = cartController.removeFromcart(new ModifyCartRequest());
        //
        assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
    }

    @Test
    void removeFromCart_NotFoundItem() {
        Mockito.doReturn(new User()).when(userRepository).findByUsername(Mockito.any());
        Mockito.doReturn(Optional.empty()).when(itemRepository).findById(Mockito.any());
        ResponseEntity<Cart> responseEntity = cartController.removeFromcart(new ModifyCartRequest());
        assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
    }

    @Test
    void removeFromCart_Success() {
        ModifyCartRequest request = new ModifyCartRequest();
        request.setQuantity(3);
        User user = createUser();
        Cart cart = createCart();
        Item item = createItem();

        List<Item> items = new ArrayList<>();
        items.add(item);
        cart.setUser(user);
        cart.setItems(items);
        user.setCart(cart);

        Mockito.doReturn(user).when(userRepository).findByUsername(Mockito.any());
        Mockito.doReturn(Optional.of(item)).when(itemRepository).findById(Mockito.any());

        ResponseEntity<Cart> responseEntity = cartController.removeFromcart(request);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(0, responseEntity.getBody().getItems().size());
    }

    private User createUser() {
        User user = new User();
        user.setId(1L);
        user.setUsername("user");
        user.setPassWord("password");
        return user;
    }

    private Cart createCart() {
        Cart cart = new Cart();
        cart.setId(1L);
        cart.setTotal(BigDecimal.ONE);
        return cart;
    }

    /**
     * Create Item
     * 
     * @return Item
     */
    private Item createItem() {
        Item item = new Item();
        item.setId(1L);
        item.setName("Item");
        item.setPrice(BigDecimal.ONE);
        item.setDescription("Description");
        return item;
    }
}
