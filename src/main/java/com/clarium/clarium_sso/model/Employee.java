package com.clarium.clarium_sso.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "Employee", schema = "dbo")
@Data
public class Employee {

    @Id
    @Column(name = "EmpID")
    private int empId;

    @Column(name = "FirstName")
    private String firstName;

    @Column(name = "LastName")
    private String lastName;

    @Column(name = "Email")
    private String email;

    @Column(name = "CreatedAt")
    private LocalDateTime createdAt;

    @Column(name = "LastModified")
    private LocalDateTime lastModified;

    @Column(name = "Profile")
    private String profile;
}
