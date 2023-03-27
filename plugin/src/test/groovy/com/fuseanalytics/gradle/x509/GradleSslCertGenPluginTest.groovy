package com.fuseanalytics.gradle.x509

import org.gradle.testfixtures.ProjectBuilder
import org.gradle.api.Project
import spock.lang.Specification

class GradleSslCertGenPluginTest extends Specification {
    void "plugin creates generateCert"() {
        given:
        Project project = ProjectBuilder.builder().build()

        when:
        project.plugins.apply("com.fuseanalytics.gradle.x509.SslCertGen")

        then:
        project.tasks.findByName("generateCert") != null
    }
}
