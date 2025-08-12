package com.clarium.clarium_sso.repository;

import com.clarium.clarium_sso.model.WorkInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface WorkInfoRepository extends JpaRepository<WorkInfo, Integer> {

    @Query("Select w.desgnId from WorkInfo w where w.empId= :empId")
    Optional<String> findDesgnIdByEmpId(@Param("empId") int empId);

    @Query("Select w.reportingManager from WorkInfo w where w.empId= :empId")
    Optional<String> findReportingManagerByEmpId(int empId);

//    Optional<List<WorkInfo>> findAll(int empId);
}
