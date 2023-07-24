package com.example.securitedemo.secr.service;

import com.example.securitedemo.secr.entities.AppRole;
import com.example.securitedemo.secr.entities.AppUser;
import com.example.securitedemo.secr.repo.AppRoleRepository;
import com.example.securitedemo.secr.repo.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
@Service
@Transactional
public class AccountServiceImpl implements AccountService {

    private AppRoleRepository appRoleRepository;
    private AppUserRepository appUserRepository;

    private PasswordEncoder passwordEncoder;

    public AccountServiceImpl(AppRoleRepository appRoleRepository, AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appRoleRepository = appRoleRepository;
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }




    @Override
    public AppUser addNewUser(AppUser appUser) {
        String pw=appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(pw)); //pour hashé le code et ne peut trouvé le mot de pass original, il se base sur la date system,
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }



    @Override
    public void addRoleToUser(String userName, String roleName) {
        AppUser appUser=appUserRepository.findByUserName(userName);
        AppRole appRole=appRoleRepository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);

    }

    @Override
    public AppUser loadUserByUsername(String userName) {


        return appUserRepository.findByUserName(userName);
    }

    @Override
    public List<AppUser> listeUsers() {
        List<AppUser>list=appUserRepository.findAll();
        return list;
    }
}
