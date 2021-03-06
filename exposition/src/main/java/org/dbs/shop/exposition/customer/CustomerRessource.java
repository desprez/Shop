package org.dbs.shop.exposition.customer;

import org.dbs.shop.application.customer.ICustomerManagement;
import org.dbs.shop.domain.Customer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotNull;

@RestController
@RequestMapping("/customers")
public class CustomerRessource {

    private static Logger logger = LoggerFactory.getLogger(CustomerRessource.class);

    @Autowired
    ICustomerManagement customerManagement;

    @PostMapping("create")
    @ResponseStatus(HttpStatus.OK)
    public void createCustomer(@NotNull @RequestBody CustomerDTO customerDTO) {
        if (customerDTO.getCustomerName() != null) {
            customerManagement.referenceCustomer(customerDTO.getCustomerName());
            logger.debug("Customers Create");
        }
    }


    @GetMapping("retrieve/{customerName}")
    public CustomerFullDTO retrieveCustomerBuName(@NotNull @PathVariable("customerName") String customerName) {
        CustomerFullDTO customerFullDto;
        Customer customer = customerManagement.retrieveCustomerByName(customerName);
        customerFullDto = new CustomerFullDTO();
        customerFullDto.setCustomerName(customer.getName());
        customerFullDto.setPassword(customer.getPassword());
        logger.debug("Customers Retrieve");

        return customerFullDto;
    }
}
