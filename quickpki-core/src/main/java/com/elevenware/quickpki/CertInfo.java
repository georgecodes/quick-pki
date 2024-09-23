package com.elevenware.quickpki;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
/**
 * @CertInfo
 *
 * Metadata which can be provided when issuing a certificate
 *
 * @see SubjectName
 */
public class CertInfo {

    private SubjectName subjectName;
    private Instant validFrom;
    private Instant validUntil;

}
