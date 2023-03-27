package com.fuseanalytics.gradle.x509

import org.gradle.testfixtures.ProjectBuilder
import org.gradle.api.Project
import spock.lang.Specification

class GradleSslCertGenPluginTest extends Specification {
    void "plugin does not create task immediately"() {
        given:
        Project project = ProjectBuilder.builder().build()

        when:
        project.plugins.apply("com.fuseanalytics.gradle.x509.SslCertGen")

        then:
        project.tasks.findByName("generateCert") == null
    }
    /*
    void "plugin creates task when extension is present"() {
        given:
        Project project = ProjectBuilder.builder().build()

        when:
        project.extensions.add("certificate", new CertificateExtension().with {
            it.commonName = "somedomain.com"
            it.organization = "Some Domain LLC"
            it.organizationUnit = "Development"
            it.city = "Niceville"
            it.region = "State"
            it.country = "US"
            it.keyPassword = "Hill.Of.Beans"
            it
        } )

        then:
        project.tasks.findByName("generateCert") != null
    }*/
}
