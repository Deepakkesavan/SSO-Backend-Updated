package com.clarium.clarium_sso.repository;

import com.clarium.clarium_sso.model.Designation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface DesignationRepository extends JpaRepository<Designation, Integer> {

    @Query("Select d.designation from Designation d where d.id = :id")
    Optional<String> findDesignationById(String id);
    //If i write without @Query, it returns whole object instead of just giving one value
}
