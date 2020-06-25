package org.dbs.shop;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@ComponentScan(basePackages = { "org.dbs.shop" })
@EnableJpaRepositories
public class SpringBootAppTest {

	public static void main(final String[] args) {
		SpringApplication.run(SpringBootAppTest.class, args);
	}
}
