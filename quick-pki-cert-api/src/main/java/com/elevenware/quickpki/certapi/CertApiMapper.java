package com.elevenware.quickpki.certapi;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.util.UUID;

interface CertApiMapper {

    @Select("""
            select issuer_info_json,
                   certificate_pem,
                   private_key_ciphertext,
                   private_key_salt,
                   private_key_iv
            from ca_material
            where id = #{id}
            """)
    CaMaterial selectCaMaterial(String id);

    @Update("""
            update ca_material
            set issuer_info_json = #{issuerInfoJson},
                certificate_pem = #{certificatePem},
                private_key_ciphertext = #{privateKeyCiphertext},
                private_key_salt = #{privateKeySalt},
                private_key_iv = #{privateKeyIv},
                created_at = now()
            where id = #{id}
            """)
    int updateCaMaterial(CaMaterialWrite material);

    @Insert("""
            insert into ca_material (
                id,
                issuer_info_json,
                certificate_pem,
                private_key_ciphertext,
                private_key_salt,
                private_key_iv
            ) values (
                #{id},
                #{issuerInfoJson},
                #{certificatePem},
                #{privateKeyCiphertext},
                #{privateKeySalt},
                #{privateKeyIv}
            )
            """)
    int insertCaMaterial(CaMaterialWrite material);

    @Insert("""
            insert into issued_certificates (
                id,
                serial_number,
                subject_dn,
                certificate_pem,
                chain_pem,
                not_before,
                not_after,
                client_id,
                created_at
            ) values (
                #{id},
                #{serialNumber},
                #{subjectDn},
                #{certificatePem},
                #{chainPem},
                #{notBefore},
                #{notAfter},
                #{clientId},
                #{createdAt}
            )
            """)
    int insertCertificate(IssuedCertificate certificate);

    @Select("""
            select id,
                   serial_number,
                   subject_dn,
                   certificate_pem,
                   chain_pem,
                   not_before,
                   not_after,
                   client_id,
                   created_at
            from issued_certificates
            where id = #{id}
            """)
    IssuedCertificate selectCertificate(UUID id);
}

record CaMaterialWrite(
        String id,
        String issuerInfoJson,
        String certificatePem,
        byte[] privateKeyCiphertext,
        byte[] privateKeySalt,
        byte[] privateKeyIv
) {
}
