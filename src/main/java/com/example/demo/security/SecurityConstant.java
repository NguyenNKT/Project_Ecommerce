package com.example.demo.security;

public class SecurityConstant {
    public final static String SECRET_KEY = "NDKey";
    public final static long EXPIRED_TIME = 5 * 24 * 60 * 60;
    public final static String SIGN_UP_URL_SERVER = "/api/user/create";
    public final static String TOKEN_PREFIX = "Bearer ";
    public final static String HEADER_STRING = "Authorization";

}
