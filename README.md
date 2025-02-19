# gradle-ssl-cert-gen

## About

Generate SSL/TLS certificates within Gradle at build time with this plugin.  This allows you to support 
end-to-end encryption in containers using self-signed certificates generated at build time.  No additional 
integrations needed.

When using containers if you want to turn on SSL/TLS to your server you'll need a certificate, but getting that 
certificate on the container can be a pain.  You can copy a pre-generated certificate, but checking that into source 
control is typically an antipattern.  Therefore, you'll need some other place in which to copy it from which means 
fragile integrations with other systems potentially.  You could use an external secrets manager, but it's complicated to
get the certificate on the file system before starting up your system.  Configuring something like "Let's Encrypt" is 
not straightforward in a container environment without creating your own images and managing that process too.  If you 
environment simply needs a self-signed certificate just to enable TLS/SSL on your server because your infrastructure 
sits behind a Load Balancer or other hardware that will present your actual trusted certificate, then this is a simple 
solution that doesn't require a lot of fancy configuration.

This is an all Java solution, so it's portable and does not rely on any additional environment specific programs or 
external requirements.  The plugin alone can create the certificate for you. 

## Usage

Declare the plugin at the top of your `build.gradle`:

```
plugins {
   id "com.fuseanalytics.gradle.sslcertgen"
}
```

Then declare the `certificate` block to configure how the key is generated:

```
certificate {
    commonName = "somedomain.com"
    organization = "Some Company"
    organizationUnit = "Engineering"
    city = "Niceville"
    region = "Georgia"
    country = "US"
    keyPassword = getProperty("certPassword")
}
```

The plugin adds a single task `generateCert` which will generate the certificate.

Those are the bare minimum parameters that must be specified.  The resulting certificate will
be saved into `${buildDir}/certificate/${project.name}.pkcs12`.  The project name will be in lower
case and any whitespace will be replaced with an underscore.

The full set of parameters for the certificate block are the following:
   * **commonName** the domain name of server the certificate will be used on.
   * **organization** the organization issuing the certificate.
   * **organizationUnit** the unit within the organization that is responsible for the certificate.
   * **city** The location of the organization.
   * **region** The region of the organization.
   * **country** The 2-letter ISO code for the country of the organization.
   * **keyPassword** The password for the private key.
   * **keyFile** The file which the certificate will be written (default `${buildDir}/certificate/${project.name}.pkcs12`).
   * **keySize** The size of the key in bits (default 2048)
   * **daysValid** The number of days the key will be valid (default 365)
