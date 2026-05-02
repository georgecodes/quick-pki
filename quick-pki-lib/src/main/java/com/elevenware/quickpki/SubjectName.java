package com.elevenware.quickpki;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SubjectName {

    private String commonName;
    private String country;
    private String organization;
    private String organizationUnit;
    private String dnQualifier;
    private String locality;
    private String stateOrProvince;

}
