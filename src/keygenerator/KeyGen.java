package keygenerator;

import algos.Tools;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public final class KeyGen
{
  public static SecretKey generateSymKey(String alg, int key_length, String[] provider)
    throws NoSuchAlgorithmException, NoSuchProviderException
  {
     KeyGenerator cleGen = KeyGenerator.getInstance(alg, Tools.getDefaultProvider(provider));
     cleGen.init(key_length, new SecureRandom());

     return cleGen.generateKey();
  }

  public static KeyPair generateAsymKeys(String alg, int key_length, String[] provider) throws NoSuchAlgorithmException, NoSuchProviderException
  {
     KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, Tools.getDefaultProvider(provider));
     kpg.initialize(4096, new SecureRandom());

     return kpg.generateKeyPair();
  }

  public static SecretKey generateOwnSymKey(String key_s, String alg, int key_length, String[] provider)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
  {
     SecretKey sk = null;

     if (provider == null)
    {
       PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
       generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(key_s.toCharArray()), new byte[key_length / 8], 65536);
       KeyParameter params = (KeyParameter)generator.generateDerivedParameters(key_length);
       sk = new SecretKeySpec(params.getKey(), 0, params.getKey().length, alg);
    }

     return sk;
  }

  public static SecretKey generateSharedDHKey(KeyPair own_key, PublicKey peer_key, String alg, String[] provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
     KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", Tools.getDefaultProvider(provider));
     keyAgreement.init(own_key.getPrivate());
     keyAgreement.doPhase(peer_key, true);

     return keyAgreement.generateSecret(alg);
  }

  public static KeyPair generateOwnDHKey(String[] provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
     ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
     KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", Tools.getDefaultProvider(provider));

     keyPairGenerator.initialize(parameterSpec);
     return keyPairGenerator.generateKeyPair();
  }

  public static KeysAndCertificate generateKeysAndCertificate()
    throws NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException, OperatorCreationException
  {
     KeyPair key_pair = generateAsymKeys("RSA", 2048, new String[0]);

     long now = System.currentTimeMillis();
     Date startDate = new Date(now);
     X500Name dnName = new X500Name("dc=Dipto");
     BigInteger certSerialNumber = new BigInteger(Long.toString(now));

     Calendar calendar = Calendar.getInstance();
     calendar.setTime(startDate);
     calendar.add(1, 1);

     Date endDate = calendar.getTime();

     ContentSigner contentSigner = new JcaContentSignerBuilder("SHA512withRSA").build(key_pair.getPrivate());

     JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, key_pair.getPublic());

     BasicConstraints basicConstraints = new BasicConstraints(true);

     certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

     X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));

     return new KeysAndCertificate(key_pair.getPrivate(), certificate);
  }

  static
  {
     Security.addProvider(new BouncyCastleProvider());
  }
}
