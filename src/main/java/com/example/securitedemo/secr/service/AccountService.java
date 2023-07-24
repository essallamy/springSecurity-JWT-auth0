package com.example.securitedemo.secr.service;

import com.example.securitedemo.secr.entities.AppRole;
import com.example.securitedemo.secr.entities.AppUser;

import java.util.List;

public interface AccountService {

    AppUser addNewUser( AppUser appUser);
    AppRole addNewRole(AppRole appRole);

    void addRoleToUser(String userName, String roleName);
    AppUser loadUserByUsername(String userName);
    List<AppUser> listeUsers();

}
