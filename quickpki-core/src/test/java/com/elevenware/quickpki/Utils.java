package com.elevenware.quickpki;

import org.bouncycastle.openssl.PEMWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class Utils {

    public static LocalDateTime dateToLocalDateTime(Date dateToConvert) {
        return dateToConvert.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }

    public static void dumpCert(X509Certificate certificate) throws IOException {
        StringWriter sw = new StringWriter();
        try (PEMWriter pw = new PEMWriter(sw)) {
            pw.writeObject(certificate);
        }
        System.out.println(sw.toString());
    }

}
