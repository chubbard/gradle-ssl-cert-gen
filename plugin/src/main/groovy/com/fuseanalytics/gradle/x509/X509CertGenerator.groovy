package com.fuseanalytics.gradle.x509

import groovy.transform.CompileStatic
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.bc.BcX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit

@CompileStatic
class X509CertGenerator {

    public static final int DEFAULT_KEY_BIT_DEPTH = 1024 * 2
    public static final int CERT_DAYS = 365

    File keyFile
    char[] keyPassword
    X500Name issuer
    X500Name subject

    int daysValid = CERT_DAYS
    int keySize = DEFAULT_KEY_BIT_DEPTH

    public X509CertGenerator(File keyFile, char[] password) {
        this.keyFile = keyFile
        this.keyPassword = password
    }

    public X509CertGenerator issuer(String commonName, String org, String orgUnit, String city, String region, String country) {
        issuer = createX500Name( commonName, org, orgUnit, city, region, country )
        return this
    }

    public KeyStore generate() {
        KeyStore ks = KeyStore.getInstance("pkcs12")

        if( !subject ) {
            subject = issuer
        }

        KeyPair keypair = generateKeyPair()

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keypair.getPrivate())
        //SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo();

        Date now = new Date()
        long daysInMillis = TimeUnit.DAYS.toMillis( daysValid )

        X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(
                issuer,
                generateSerialNumber(),
                now,
                new Date( now.getTime() + daysInMillis ),
                subject,
                keypair.getPublic())
                .addExtension( Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(keypair.getPublic()) )
                .addExtension( Extension.basicConstraints, true, new BasicConstraints(false))

        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign
                | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                | KeyUsage.dataEncipherment | KeyUsage.cRLSign)

        generator.addExtension(Extension.keyUsage, false, usage)

        ASN1EncodableVector purposes = new ASN1EncodableVector()
        purposes.add(KeyPurposeId.id_kp_serverAuth)
        purposes.add(KeyPurposeId.id_kp_clientAuth)
        purposes.add(KeyPurposeId.anyExtendedKeyUsage)

        generator.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes))

        X509CertificateHolder certificateHolder = generator.build(signer)
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder)

        ks.load(null, keyPassword)
        ks.setKeyEntry("gradle_ssl_cert", keypair.getPrivate(), keyPassword, [cert] as Certificate[] )
        if( !keyFile.parentFile.exists() ) keyFile.parentFile.mkdirs()
        keyFile.withOutputStream {
            ks.store( it, keyPassword )
        }
        return ks
    }

    private X500Name createX500Name(String commonName, String org, String orgUnit, String city, String region, String country) {
        return new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, commonName)
                .addRDN(BCStyle.O, org)
                .addRDN(BCStyle.OU, orgUnit)
                .addRDN(BCStyle.L, city)
                .addRDN(BCStyle.ST, region)
                .addRDN(BCStyle.C, country)
                .build()
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize( keySize )
        return generator.generateKeyPair()
    }

    private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) throws IOException {
        new ASN1InputStream(new ByteArrayInputStream(key.getEncoded())).withStream {is ->
            ASN1Sequence seq = (ASN1Sequence) is.readObject()
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(seq)
            return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info)
        }
    }

    private BigInteger generateSerialNumber() {
        Random random = new SecureRandom()
        return new BigInteger(256,random)
    }

    X509CertGenerator keySize(int size) {
        this.keySize = size
        return this
    }

    X509CertGenerator daysValid(int days) {
        this.daysValid = days
        return this
    }
}
