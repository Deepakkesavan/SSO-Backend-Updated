package com.clarium.clarium_sso.model;

import jakarta.persistence.*;
import lombok.Data;
//import lombok.Data;
import java.time.LocalDate;
import java.util.UUID;

@Entity
@Table(name = "WorkInfo", schema = "dbo")
@Data
public class WorkInfo {

    @Id
    @Column(name = "EmpID")
    private Integer empId;  // assuming varchar(30)

    @Column(name = "LocID")
    private Integer locId;

    @Column(name = "DeptID")
    private Integer deptId;

    @Column(name = "SourceOfHire", length = 100)
    private String sourceOfHire;

    @Column(name = "DOJ")
    private LocalDate doj;

    @Column(name = "DOC")
    private LocalDate doc;

    @Column(name = "Status", length = 50)
    private String status;

    @Column(name = "CurrExp", length = 50)
    private String currExp;

    @Column(name = "TotalExp", length = 50)
    private String totalExp;

    @Column(name = "RoleID")
    private Integer roleId;

    @Column(name = "BID")
    private Integer bid;

    @Column(name = "EmailTriggerStatus", length = 50)
    private String emailTriggerStatus;

    @Column(name = "TransferFromDate")
    private LocalDate transferFromDate;

    @Column(name = "TypeID")
    private Integer typeId;

    @Column(name = "DesgnID", columnDefinition = "uniqueidentifier")
    private UUID desgnId;

    @Column(name = "ReportingManager", length = 100)
    private String reportingManager;

    @Column(name = "ProjId")
    private Integer projId;
}

