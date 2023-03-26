package com.fuseanalytics.gradle.x509

import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional

class CertificateExtension {

    public static final int DEFAULT_VALIDITY = 365

    public static final int DEFAULT_KEY_SIZE = 2048

    @Input
    String commonName

    @Input
    String organization

    @Input
    String organizationUnit

    @Input
    String city

    @Input
    String region

    @Input
    String country

    @Input
    String keyPassword

    @InputFile
    @Optional
    File keyFile

    @Optional
    @Input
    int daysValid = DEFAULT_VALIDITY

    @Optional
    @Input
    int keySize = DEFAULT_KEY_SIZE
}
