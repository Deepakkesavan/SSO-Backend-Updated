package com.clarium.clarium_sso.repository;

import com.clarium.clarium_sso.model.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface EmployeeRepository extends JpaRepository<Employee, Integer> {

    // Find email exists or not
    Boolean existsByEmail(String email);

    //Find employee id by email
    @Query("SELECT e.empId FROM Employee e WHERE e.email = :email")
    Optional<Integer> findEmpIdByEmail(@Param("email") String email);
}
