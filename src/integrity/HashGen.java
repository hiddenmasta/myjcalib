/*Dipto, a reasonably secure end-to-end desktop chat app built by the paranoid, for the paranoid
Copyright (C) 2018 Hiddenmaster

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.*/

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package integrity;

import algos.CryptoProprieties;
import algos.Tools;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 *
 * @author anon
 */
public final class HashGen {

    static{
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static Object[] getSalt()
    {
        Object[] salt = new Object[2];

        salt[0] = (new Date()).getTime(); // Long
        salt[1] = new SecureRandom().generateSeed(16); // byte[]

        return salt;
    }

    public static byte[] getSaltedHash(String string, Object[] salt, String... provider) throws
    IOException,
    NoSuchAlgorithmException,
    NoSuchProviderException
    {
        byte[] hash = null;

        try(ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos))
        {

            List<byte[]> list = new ArrayList<>();
            list.add(string.getBytes("UTF-8"));

            oos.writeObject(salt[0]);
            oos.writeObject(salt[1]);

            list.add(baos.toByteArray());

            hash = HashGen.getHash(list, CryptoProprieties.HASH_ALG, provider);
        }

        return hash;
    }

    public static byte [] getHash(List<byte []> plain_text, String alg, String... provider) throws
    NoSuchAlgorithmException,
    NoSuchProviderException
    {
        MessageDigest md = MessageDigest.getInstance(alg, Tools.getDefaultProvider(provider));

        plain_text.stream().forEach((tab) -> {
            md.update(tab);
        });

        return md.digest();
    }

    public static boolean areHashEquals(byte [] hash1, byte [] hash2)
    {
        return MessageDigest.isEqual(hash1, hash2);
    }
}
