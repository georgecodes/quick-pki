package com.elevenware.quickpki.certapi;

import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;

import javax.sql.DataSource;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;

final class CertApiRepository {

    private static final String DEFAULT_CA_ID = "default";

    private final SqlSessionFactory sessionFactory;

    CertApiRepository(DataSource dataSource) {
        this.sessionFactory = MyBatis.sessionFactory(dataSource);
    }

    Optional<CaMaterial> loadCaMaterial() {
        return read(mapper -> Optional.ofNullable(mapper.selectCaMaterial(DEFAULT_CA_ID)));
    }

    void saveCaMaterial(CaMaterial material) {
        CaMaterialWrite row = new CaMaterialWrite(
                DEFAULT_CA_ID,
                material.issuerInfoJson(),
                material.certificatePem(),
                material.privateKeyCiphertext(),
                material.privateKeySalt(),
                material.privateKeyIv());
        write(mapper -> {
            if (mapper.updateCaMaterial(row) == 0) {
                mapper.insertCaMaterial(row);
            }
        });
    }

    void saveCertificate(IssuedCertificate certificate) {
        write(mapper -> mapper.insertCertificate(certificate));
    }

    Optional<IssuedCertificate> loadCertificate(UUID id) {
        return read(mapper -> Optional.ofNullable(mapper.selectCertificate(id)));
    }

    private void write(Consumer<CertApiMapper> work) {
        try (SqlSession session = sessionFactory.openSession(false)) {
            try {
                work.accept(session.getMapper(CertApiMapper.class));
                session.commit();
            } catch (RuntimeException e) {
                session.rollback();
                throw e;
            }
        } catch (RuntimeException e) {
            throw new IllegalStateException("Database update failed", e);
        }
    }

    private <T> T read(Function<CertApiMapper, T> work) {
        try (SqlSession session = sessionFactory.openSession(true)) {
            return work.apply(session.getMapper(CertApiMapper.class));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Database query failed", e);
        }
    }
}
