package com.na.auth.service.impl;

import com.na.auth.model.AuthUserModel;
import com.na.auth.service.INaSecurityService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class NaSecurityServiceImpl implements INaSecurityService {
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        AuthUserModel model = new AuthUserModel();
        return model;
    }
}
