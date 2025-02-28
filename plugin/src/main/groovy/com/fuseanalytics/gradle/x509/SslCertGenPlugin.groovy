/*
 * This Groovy source file was generated by the Gradle 'init' task.
 */
package com.fuseanalytics.gradle.x509

import org.gradle.api.Project
import org.gradle.api.Plugin

class SslCertGenPlugin implements Plugin<Project> {

    void apply(Project project) {
        CertificateExtension certificate = project.extensions.create( "certificate", CertificateExtension )
        project.tasks.register("generateCert", X509Certificate, project, certificate )
    }
}
