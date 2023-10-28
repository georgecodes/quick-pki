package com.elevenware.quickpki;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.concurrent.TimeUnit;

@Data
@Builder
public class CertInfo {

    private String commonName;
    private LocalDateTime startDate;
    private LocalDateTime endDate;

}
