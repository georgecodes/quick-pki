package com.elevenware.quickpki;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class CertInfo {

    private SubjectName subjectName;
    private Instant validFrom;
    private Instant validUntil;

}
