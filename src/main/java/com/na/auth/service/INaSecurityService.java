package com.na.auth.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface INaSecurityService extends UserDetailsService {
    /**
     * loadUserByUsername
     * @param s s
     * @return UserDetails
     * @throws UsernameNotFoundException e
     */
    @Override
    UserDetails loadUserByUsername(String s) throws UsernameNotFoundException;
}
