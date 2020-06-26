package org.dbs.shop.application.order;

import java.time.LocalDate;
import java.util.List;

import org.dbs.shop.domain.Customer;
import org.dbs.shop.domain.IRepositoryCustomer;
import org.dbs.shop.domain.Item;
import org.dbs.shop.domain.Order;
import org.dbs.shop.domain.OrderNumberGenerator;
import org.dbs.shop.domain.order.IRepositoryOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OrderManagementImpl implements IOrderManagement {

	@Autowired
	private IRepositoryCustomer repositoryCustomer;

	@Autowired
	private IRepositoryOrder repositoryOrder;

	@Override
	public Order createOrder(final String customerName, final List<Item> items) {

		final Customer customer = repositoryCustomer.findByName(customerName);

		final Order order = new Order(customer, OrderNumberGenerator.generate(), LocalDate.now());
		for (final Item item : items) {
			order.addItem(item);
		}
		repositoryOrder.save(order);
		return order ;
	}

}