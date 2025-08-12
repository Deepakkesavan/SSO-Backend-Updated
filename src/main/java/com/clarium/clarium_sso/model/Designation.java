package com.clarium.clarium_sso.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "Designation", schema = "dbo")
@Data
public class Designation {

    @Id
    @Column(name = "DesgID")
    private Integer designationId;

    @Column(name = "Desg")
    private String designation;

    @Column(name = "Id")
    private String id;
}
