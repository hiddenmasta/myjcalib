package authenticity;

import algos.Tools;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignedObject;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class SignatureGen
{
  public static byte[] asymSign(byte[] plain_text, String alg, PrivateKey key, String[] provider)
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException
  {
     Signature sign = Signature.getInstance(alg, Tools.getDefaultProvider(provider));
     sign.initSign(key);
     sign.update(plain_text);

     return sign.sign();
  }

  public static byte[] symSign(byte[] plain_text, String alg, SecretKey key, String[] provider)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
  {
     Mac hmac = Mac.getInstance(alg, Tools.getDefaultProvider(provider));
     hmac.init(key);

     return hmac.doFinal(plain_text);
  }

  public static boolean verifySymSign(byte[] plain_text, byte[] signature, String alg, SecretKey key, String[] provider)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
  {
     return MessageDigest.isEqual(signature, symSign(plain_text, alg, key, new String[] { Tools.getDefaultProvider(provider) }));
  }

  public static boolean verifyAsymSign(byte[] plain_text, byte[] signature, String alg, PublicKey key, String[] provider)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
  {
     Signature sign = Signature.getInstance(alg, Tools.getDefaultProvider(provider));
     sign.initVerify(key);
     sign.update(plain_text);

     return sign.verify(signature);
  }

  public static SignedObject signObject(Serializable obj, PrivateKey key, String alg, String[] provider)
    throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException
  {
     return new SignedObject(obj, key, Signature.getInstance(alg, Tools.getDefaultProvider(provider)));
  }

  public static boolean verifyObjectSign(SignedObject obj, PublicKey key, String alg, String[] provider)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
  {
     return obj.verify(key, Signature.getInstance(alg, Tools.getDefaultProvider(provider)));
  }

  static
  {
     Security.addProvider(new BouncyCastleProvider());
  }
}
