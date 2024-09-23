package com.elevenware.quickpki;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
/**
 * @SubjectName
 *
 * Metadata which models a distinguished name
 *
 * @see IssuerInfo
 */
public class SubjectName {

    private String commonName;
    private String country;
    private String organization;
    private String organizationUnit;
    private String dnQualifier;
    private String locality;
    private String stateOrProvince;

}
