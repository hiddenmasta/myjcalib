package keygenerator;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class KeysAndCertificate
{
  private final PrivateKey prk;
  private final X509Certificate cert;

  public KeysAndCertificate(PrivateKey prk, X509Certificate cert)
  {
     this.prk = prk;
     this.cert = cert;
  }

  public PrivateKey getPrk() {
     return this.prk;
  }

  public X509Certificate getCert() {
     return this.cert;
  }
}
