package com.fuseanalytics.gradle.x509

import org.gradle.api.DefaultTask
import org.gradle.api.Project
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

import javax.inject.Inject
import java.security.KeyStore

abstract class X509Certificate extends DefaultTask {

    public static final int DEFAULT_VALIDITY = 365

    public static final int DEFAULT_KEY_SIZE = 2048

    @Input
    abstract Property<String> getCommonName()

    @Input
    abstract Property<String> getOrganization()

    @Input
    abstract Property<String> getOrganizationUnit()

    @Input
    abstract Property<String> getCity()

    @Input
    abstract Property<String> getRegion()

    @Input
    abstract Property<String> getCountry()

    @Input
    abstract Property<String> getPassword()

    @OutputFile
    @Optional
    abstract Property<File> getKeyFile()

    @Input
    @Optional
    abstract Property<Integer> getDaysValid()

    @Input
    @Optional
    abstract Property<Integer> getKeySize()

    X509Certificate(Project project) {
        description = "Generates a self-signed X509 Certificate according to the configuration."
        group = "certificate"

        keyFile.convention(new File( project.rootDir, "build/certificate/${project.name.toLowerCase().replaceAll(/\s/,"_")}.pkcs12" ))
        daysValid.convention(DEFAULT_VALIDITY)
        keySize.convention(DEFAULT_KEY_SIZE)
    }

    @Inject
    X509Certificate(Project project, CertificateExtension certificate ) {
        this( project )

        if( certificate != null ) {
            commonName.set(certificate.commonName)
            organization.set(certificate.organization)
            organizationUnit.set(certificate.organizationUnit)
            city.set(certificate.city)
            region.set(certificate.region)
            country.set(certificate.country)
            password.set(certificate.keyPassword)
            if( certificate.keyFile.isPresent() ) keyFile.set(certificate.keyFile)
            if( certificate.keySize.isPresent() ) keySize.set(certificate.keySize)
            if( certificate.daysValid.isPresent() ) daysValid.set(certificate.daysValid)
        }
    }

    @TaskAction
    public void generateCert() {
        logger.debug("Creating Certificate using keyFile={}, keySize={}, daysValid={}, [CN={}, O={}, OU={}, L={}, P={}, C={}]",
                keyFile.get(),
                keySize.get(),
                daysValid.get(),
                commonName.get(),
                organization.get(),
                organizationUnit.get(),
                city.get(),
                region.get(),
                country.get())
        KeyStore ks = new X509CertGenerator(keyFile.get(), password.get().getChars())
                .issuer(commonName.get(),
                        organization.get(),
                        organizationUnit.get(),
                        city.get(),
                        region.get(),
                        country.get()
                )
                .keySize(keySize.getOrElse(DEFAULT_KEY_SIZE))
                .daysValid(daysValid.getOrElse(DEFAULT_VALIDITY))
                .generate()
    }
}
