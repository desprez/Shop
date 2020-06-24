package org.dbs.shop.infratructure;

import org.dbs.shop.domain.Customer;
import org.dbs.shop.domain.CustomerAllReadyExistException;
import org.dbs.shop.domain.IRepositoryCustomer;

public class RepositoryCustomerImpl implements IRepositoryCustomer {

    ICustomerJpaRepository customerJpaRepository;

    @Override
    public void save(Customer customer) throws CustomerAllReadyExistException {

        CustomerEntity customerEntity = customerJpaRepository.findByUserName(customer.getName());
        if (customerEntity == null) {
            customerEntity = new CustomerEntity();
            customerEntity.setUserName(customer.getName());
            customerEntity.setPassword(customer.getPassword());
            customerJpaRepository.save(customerEntity);
        } else {
            throw new CustomerAllReadyExistException(customer.getName());
        }

    }
}
