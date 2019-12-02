using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

class Program {
    private static RSAParameters publicKey;
    private static RSAParameters privateKey;
    public enum KeySizes {
        SIZE_512 = 512,
        SIZE_1024 = 1024,
        SIZE_2048 = 2048,
        SIZE_952 = 952,
        SIZE_1369 = 1369
    }

    static void Main (string[] args) {
        Console.WriteLine("Write message to be encrypted:");

        string message = Console.ReadLine();
        generateKeys ();

        //encrypt message then store result in file
        byte[] encrypted = Encrypt (Encoding.UTF8.GetBytes (message));
        File.WriteAllBytes (Path.GetDirectoryName (Assembly.GetExecutingAssembly ().Location) + @"\encrypted.txt", encrypted);
        Console.WriteLine ("Encrypted data written to file\n");



        //read encrypted data from file and decrypt it
        byte[] from_file = File.ReadAllBytes (Path.GetDirectoryName (Assembly.GetExecutingAssembly ().Location) + @"\encrypted.txt");
        byte[] decrypted = Decrypt (from_file);
        Console.WriteLine ("Encrypted data from file read and decrypted\n");


        Console.WriteLine ("Original\n\t " + message + "\n");
        Console.WriteLine ("Encrypted\n\t" + BitConverter.ToString (encrypted).Replace ("-", "") + "\n");
        Console.WriteLine ("Decrypted\n\t" + Encoding.UTF8.GetString (decrypted));

        Console.ReadLine ();
    }

    static void generateKeys () {
        using (var rsa = new RSACryptoServiceProvider (2048)) {
            rsa.PersistKeyInCsp = false; //Don't store the keys in a key container
            publicKey = rsa.ExportParameters (false);
            privateKey = rsa.ExportParameters (true);
            
            //store the keys in file
            File.WriteAllText(Path.GetDirectoryName (Assembly.GetExecutingAssembly ().Location) + @"\pubKey.xml", KeyToString(publicKey));
            File.WriteAllText(Path.GetDirectoryName (Assembly.GetExecutingAssembly ().Location) + @"\priKey.xml", KeyToString(privateKey));

            Console.WriteLine("Keys writen to file\n");
        }
    }

    static byte[] Encrypt (byte[] input) {
        byte[] encrypted;
        using (var rsa = new RSACryptoServiceProvider (2048)) {
            rsa.PersistKeyInCsp = false;

            //get public key from file
            rsa.ImportParameters (StringToKey(File.ReadAllText(Path.GetDirectoryName (Assembly.GetExecutingAssembly ().Location) + @"\pubKey.xml")));

            encrypted = rsa.Encrypt (input, true);
        }
        return encrypted;
    }

    static byte[] Decrypt (byte[] input) {
        byte[] decrypted;
        using (var rsa = new RSACryptoServiceProvider (2048)) {
            rsa.PersistKeyInCsp = false;

            //get private key from file
            rsa.ImportParameters (StringToKey(File.ReadAllText(Path.GetDirectoryName (Assembly.GetExecutingAssembly ().Location) + @"\priKey.xml")));

            decrypted = rsa.Decrypt (input, true);
        }
        return decrypted;
    }

    //converting the public key into a string representation
      static string KeyToString(RSAParameters key)
      {
        //we need some buffer
        var sw = new System.IO.StringWriter();
        //we need a serializer
        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
        //serialize the key into the stream
        xs.Serialize(sw, key);
        //get the string from the stream

        return sw.ToString();
      }

      //converting it back
      static RSAParameters StringToKey(string stringkey)
      {
        //get a stream from the string
        var sr = new System.IO.StringReader(stringkey);
        //we need a deserializer
        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
        //get the object back from the stream

        return (RSAParameters)xs.Deserialize(sr);
      }
}