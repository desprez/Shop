package org.dbs.shop.application.customer;

import org.apache.commons.lang3.RandomStringUtils;
import org.dbs.shop.domain.Customer;
import org.dbs.shop.domain.AllReadyExistException;
import org.dbs.shop.domain.NotFoundException;
import org.dbs.shop.domain.IRepositoryCustomer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CustomerManagementImpl implements ICustomerManagement {

    public static final String DEFAULTPASSWORD = "defaultpassword";

    @Autowired
    private IRepositoryCustomer repositoryCustomer;

    @Override
    public void referenceCustomer(String customerName) throws AllReadyExistException {
        // Creer un customer
        RandomStringUtils.randomAlphanumeric(10);
        Customer customer = new Customer(customerName, RandomStringUtils.randomAlphanumeric(10));

        // Reference un customer
        repositoryCustomer.save(customer);
    }

    @Override
    public Customer retrieveCustomerByName(String customerName) throws NotFoundException {
        // Reference un customer

        return repositoryCustomer.findByName(customerName);
    }
}
