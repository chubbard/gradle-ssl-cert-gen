package com.fuseanalytics.gradle.x509

import org.gradle.api.provider.Property

abstract class CertificateExtension {

    abstract Property<String> getCommonName()

    abstract Property<String> getOrganization()

    abstract Property<String> getOrganizationUnit()

    abstract Property<String> getCity()

    abstract Property<String> getRegion()

    abstract Property<String> getCountry()

    abstract Property<String> getKeyPassword()

    abstract Property<File> getKeyFile()

    abstract Property<Integer> getDaysValid()

    abstract Property<Integer> getKeySize()
}
