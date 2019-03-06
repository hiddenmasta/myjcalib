package confidentiality;

import Exceptions.InvalidCipherNumberException;
import Exceptions.InvalidInitializationVectorException;
import algos.Tools;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class Decryption
{
  public static byte[] asymDec(byte[] cipher_text, String alg, PrivateKey key, String[] provider)
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
  {
     Cipher dechiffrement_RSA = Cipher.getInstance(alg, Tools.getDefaultProvider(provider));
     dechiffrement_RSA.init(2, key);

     return dechiffrement_RSA.doFinal(cipher_text);
  }

  public static byte[] symDec(byte[] cipher_text, String alg, SecretKey key, byte[] init_vector, String[] provider)
    throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidInitializationVectorException
  {
     Cipher dechiffrement = Cipher.getInstance(alg, Tools.getDefaultProvider(provider));

     if (alg.contains("CBC"))
    {
       if (init_vector == null) {
         throw new InvalidInitializationVectorException("The initialization vector parameter can't be null if you use CBC chaining");
      }
       dechiffrement.init(2, key, new IvParameterSpec(init_vector));
    }
    else
    {
       dechiffrement.init(2, key);
    }
     return dechiffrement.doFinal(cipher_text);
  }

  public static Object sealedObjectDec(SealedObject sealed_object, Key key, String[] provider)
    throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException
  {
     return sealed_object.getObject(key, Tools.getDefaultProvider(provider));
  }

  public static Object sealedObjectMultipleDec(SealedObject sealed_obj, List<SecretKey> keys, String[] provider)
    throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException
  {
     Object obj = null;

     for (int i = keys.size() - 1; i >= 0; i--) {
       if (i == 0)
         obj = sealedObjectDec(sealed_obj, (Key)keys.get(i), provider);
      else {
         sealed_obj = (SealedObject)sealedObjectDec(sealed_obj, (Key)keys.get(i), provider);
      }
    }
     return obj;
  }

  public static byte[] multipleSymDec(int nb_dec, byte[] cipher_text, List<String> algos, List<SecretKey> keys, byte[] init_vector, String[] provider)
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidCipherNumberException, InvalidAlgorithmParameterException, InvalidInitializationVectorException
  {
     if (nb_dec <= 0) {
       throw new InvalidCipherNumberException("First parameter must be > 0");
    }
     if ((nb_dec != algos.size()) || (nb_dec != keys.size())) {
       throw new InvalidCipherNumberException("The number of keys/algos doesn't match the first parameter");
    }
     byte[] plain_text = cipher_text;

     for (int i = nb_dec - 1; i >= 0; i--) {
       plain_text = symDec(plain_text, (String)algos.get(i), (SecretKey)keys.get(i), init_vector, provider);
    }
     return plain_text;
  }

  static
  {
     Security.addProvider(new BouncyCastleProvider());
  }
}
