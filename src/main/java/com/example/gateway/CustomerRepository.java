package com.example.gateway;

import com.example.commanentity.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface CustomerRepository extends JpaRepository<Customer,String> {

    @Query("SELECT c FROM Customer c WHERE c.emailid = :email AND c.status = 1")
    Customer findByEmailid(String email);

    @Query("SELECT count(a.id) FROM Customer a WHERE a.session_token =:token AND a.status = 1")
    int countBySessionTokenAndStatus(String token);
}
