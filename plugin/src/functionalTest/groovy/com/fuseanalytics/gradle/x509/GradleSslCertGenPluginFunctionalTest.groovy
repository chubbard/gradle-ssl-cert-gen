/*
 * This Groovy source file was generated by the Gradle 'init' task.
 */
package com.fuseanalytics.gradle.x509

import org.gradle.testkit.runner.BuildResult
import org.gradle.testkit.runner.TaskOutcome
import spock.lang.Specification
import spock.lang.TempDir
import org.gradle.testkit.runner.GradleRunner

import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * A simple functional test for the 'com.fuseanalytics.gradle.x509.SslCertGen' plugin.
 */
class GradleSslCertGenPluginFunctionalTest extends Specification {
    @TempDir
    private File projectDir

    private getBuildFile() {
        new File(projectDir, "build.gradle")
    }

    private getSettingsFile() {
        new File(projectDir, "settings.gradle")
    }

    def "run default generateCert"() {
        given:
        settingsFile << ""
        buildFile << """
plugins {
    id('com.fuseanalytics.gradle.sslcertgen')
}

certificate {
    commonName = "somedomain.com"
    organization = "Some Domain LLC"
    organizationUnit = "IT"
    city = "Niceville"
    region = "State"
    country = "US"
    keyPassword = "Hill of Beans!"
}
"""
        File certFile = new File( projectDir, "build/certificate/${projectDir.name}.pkcs12")
        assert !certFile.exists()
        when:
        GradleRunner runner = GradleRunner.create()
                .forwardOutput()
                .withPluginClasspath()
                .withArguments("generateCert")
                .withProjectDir(projectDir)
                .withDebug(true)
        BuildResult result = runner.build()
        then:
        result.task(":generateCert")?.outcome == TaskOutcome.SUCCESS
        certFile.exists()
        certFile.length() > 0

        when:
        KeyStore ks = KeyStore.getInstance("pkcs12")
        certFile.withInputStream {
            ks.load( it, "Hill of Beans!".getChars() )
        }
        then:
        ks.containsAlias("gradle_ssl_cert")
        ks.isKeyEntry("gradle_ssl_cert")
        !ks.isCertificateEntry("gradle_ssl_cert")
        ks.size() == 1
        X509Certificate cert = ks.getCertificate("gradle_ssl_cert")
        cert.issuerX500Principal.name == "C=US,ST=State,L=Niceville,OU=IT,O=Some Domain LLC,CN=somedomain.com"
        cert.getPublicKey().getModulus().bitLength() == 2048
    }

    def "run custom generateCert"() {
        given:
        settingsFile << ""
        buildFile << """
plugins {
    id('com.fuseanalytics.gradle.sslcertgen')
}

certificate {
    commonName = "somedomain.com"
    organization = "Some Domain LLC"
    organizationUnit = "IT"
    city = "Niceville"
    region = "State"
    country = "US"
    keyPassword = "Hill of Beans!"
    keyFile = file("\${buildDir}/x509/custom.pkcs12")
    keySize = 1024
    daysValid = 128
}
"""
        File certFile = new File( projectDir, "build/x509/custom.pkcs12")
        assert !certFile.exists()
        when:
        GradleRunner runner = GradleRunner.create()
                .forwardOutput()
                .withPluginClasspath()
                .withArguments("generateCert")
                .withProjectDir(projectDir)
                .withDebug(true)
        BuildResult result = runner.build()
        then:
        result.task(":generateCert")?.outcome == TaskOutcome.SUCCESS
        certFile.exists()
        certFile.length() > 0

        when:
        KeyStore ks = KeyStore.getInstance("pkcs12")
        certFile.withInputStream {
            ks.load( it, "Hill of Beans!".getChars() )
        }
        then:
        ks.containsAlias("gradle_ssl_cert")
        ks.isKeyEntry("gradle_ssl_cert")
        !ks.isCertificateEntry("gradle_ssl_cert")
        ks.size() == 1
        X509Certificate cert = ks.getCertificate("gradle_ssl_cert")
        cert.issuerX500Principal.name == "C=US,ST=State,L=Niceville,OU=IT,O=Some Domain LLC,CN=somedomain.com"
        cert.getPublicKey().getModulus().bitLength() == 1024
    }
}
