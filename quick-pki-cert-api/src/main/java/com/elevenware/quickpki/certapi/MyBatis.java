package com.elevenware.quickpki.certapi;

import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;

import javax.sql.DataSource;
import java.util.UUID;

final class MyBatis {

    private MyBatis() {
    }

    static SqlSessionFactory sessionFactory(DataSource dataSource) {
        Environment environment = new Environment("quick-pki-cert-api", new JdbcTransactionFactory(), dataSource);
        org.apache.ibatis.session.Configuration configuration = new org.apache.ibatis.session.Configuration(environment);
        configuration.setMapUnderscoreToCamelCase(true);
        configuration.getTypeHandlerRegistry().register(UUID.class, new UuidTypeHandler());
        configuration.addMapper(CertApiMapper.class);
        return new SqlSessionFactoryBuilder().build(configuration);
    }
}
