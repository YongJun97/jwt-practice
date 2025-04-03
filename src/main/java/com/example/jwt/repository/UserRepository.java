package com.example.jwt.repository;

import com.example.jwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;



public interface UserRepository extends JpaRepository<UserEntity,Integer> {

    Boolean existsByUsername(String username);

}
