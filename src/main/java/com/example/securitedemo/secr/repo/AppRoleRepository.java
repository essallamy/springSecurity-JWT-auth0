package com.example.securitedemo.secr.repo;

import com.example.securitedemo.secr.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {
  AppRole findByRoleName (String roleName) ;
}
