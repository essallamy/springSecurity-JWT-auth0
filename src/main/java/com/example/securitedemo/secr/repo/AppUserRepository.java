package com.example.securitedemo.secr.repo;

import com.example.securitedemo.secr.entities.AppRole;
import com.example.securitedemo.secr.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {
AppUser findByUserName(String userName);


}
