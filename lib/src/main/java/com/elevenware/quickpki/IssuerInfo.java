package com.elevenware.quickpki;

import lombok.Builder;
import lombok.Data;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Data
@Builder
public class IssuerInfo {

    private SubjectName subjectName;
    @Builder.Default
    private Instant validFrom = Instant.now();
    @Builder.Default
    private Instant validUntil = Instant.now().plus(1, ChronoUnit.DAYS);
    @Builder.Default
    private Duration defaultLifespan = Duration.ofDays(1L);

}
